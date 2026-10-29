import { spawn } from "child_process";
import * as path from "path";
import * as fs from "fs/promises";
import * as syncFs from "fs";
import type {
  ToolName,
  ToolStatus,
  ToolRunner,
  ToolRunOptions,
  ToolRunOutput,
  SeverityCounts,
} from "./types.js";
import { readSarifFile, countFindings } from "./sarif.js";

/**
 * Safely resolves an executable name to its full binary path on the filesystem.
 * Checks environment overrides first (e.g. TRIVY_PATH, SEMGREP_PATH, GITLEAKS_PATH),
 * then searches PATH using platform-appropriate extensions (.exe, .cmd, .bat on Windows),
 * and checks known tool directories (e.g. WinGet Links, Python user Scripts).
 */
export function resolveExecutable(name: string): string | null {
  const envKey = `${name.toUpperCase()}_PATH`;
  const envVal = process.env[envKey];
  if (envVal && syncFs.existsSync(envVal)) {
    return envVal;
  }

  // If already an absolute or relative path that exists
  if (path.isAbsolute(name) || name.includes(path.sep)) {
    if (syncFs.existsSync(name)) return name;
  }

  const pathEnv = process.env.PATH || "";
  const dirs = pathEnv.split(path.delimiter).filter(Boolean);
  const isWindows = process.platform === "win32";

  if (isWindows) {
    // Add known Windows tool locations to search if not already present
    const localAppData = process.env.LOCALAPPDATA;
    const appData = process.env.APPDATA;

    if (localAppData) {
      const wingetLinks = path.join(localAppData, "Microsoft", "WinGet", "Links");
      if (syncFs.existsSync(wingetLinks) && !dirs.includes(wingetLinks)) {
        dirs.push(wingetLinks);
      }
    }

    if (appData) {
      const pyUserScripts = path.join(appData, "Python", "Python313", "Scripts");
      if (syncFs.existsSync(pyUserScripts) && !dirs.includes(pyUserScripts)) {
        dirs.push(pyUserScripts);
      }
      // Also discover any Python*\Scripts under AppData\Python or AppData\Roaming\Python
      const pyBase = path.join(appData, "Python");
      if (syncFs.existsSync(pyBase)) {
        try {
          const entries = syncFs.readdirSync(pyBase);
          for (const entry of entries) {
            const scripts = path.join(pyBase, entry, "Scripts");
            if (syncFs.existsSync(scripts) && !dirs.includes(scripts)) {
              dirs.push(scripts);
            }
          }
        } catch {}
      }
    }

    if (localAppData) {
      const pyProgBase = path.join(localAppData, "Programs", "Python");
      if (syncFs.existsSync(pyProgBase)) {
        try {
          const entries = syncFs.readdirSync(pyProgBase);
          for (const entry of entries) {
            const scripts = path.join(pyProgBase, entry, "Scripts");
            if (syncFs.existsSync(scripts) && !dirs.includes(scripts)) {
              dirs.push(scripts);
            }
          }
        } catch {}
      }
    }

    const trivyToolDir = "C:\\Tools\\Trivy";
    if (syncFs.existsSync(trivyToolDir) && !dirs.includes(trivyToolDir)) {
      dirs.push(trivyToolDir);
    }
  }

  const extensions = isWindows
    ? (process.env.PATHEXT || ".EXE;.CMD;.BAT;.COM")
        .split(";")
        .map((e) => e.toLowerCase())
    : [""];

  // Candidate names to check (for semgrep, also check pysemgrep on Windows)
  const candidateNames = [name];
  if (name.toLowerCase() === "semgrep" && isWindows) {
    // pysemgrep runs natively on Windows without wrapper shim issues
    candidateNames.unshift("pysemgrep");
  }

  for (const candidateName of candidateNames) {
    for (const dir of dirs) {
      const candidateDirect = path.join(dir, candidateName);
      if (syncFs.existsSync(candidateDirect)) {
        try {
          const stat = syncFs.statSync(candidateDirect);
          if (stat.isFile()) return candidateDirect;
        } catch {
          // Continue searching
        }
      }

      if (isWindows) {
        for (const ext of extensions) {
          const candidate = path.join(dir, `${candidateName}${ext}`);
          if (syncFs.existsSync(candidate)) {
            try {
              const stat = syncFs.statSync(candidate);
              if (stat.isFile()) return candidate;
            } catch {
              // Continue searching
            }
          }
        }
      }
    }
  }

  return null;
}

/**
 * Base abstract class for security scanner tool runners.
 */
export abstract class BaseToolRunner implements ToolRunner {
  abstract readonly name: ToolName;
  abstract readonly executable: string;

  /**
   * Checks whether the tool CLI is installed and accessible on PATH.
   */
  async isAvailable(): Promise<boolean> {
    const resolved = resolveExecutable(this.executable);
    if (!resolved) {
      return false;
    }

    return new Promise<boolean>((resolve) => {
      try {
        const binDir = path.dirname(resolved);
        const versionArg = this.name === "gitleaks" ? ["version"] : ["--version"];
        const proc = spawn(resolved, versionArg, {
          shell: false,
          stdio: "ignore",
          env: {
            ...process.env,
            PYTHONUTF8: "1",
            PATH: `${binDir}${path.delimiter}${process.env.PATH || ""}`,
          },
        });

        const timer = setTimeout(() => {
          proc.kill("SIGTERM");
          resolve(false);
        }, 5000);

        proc.on("error", () => {
          clearTimeout(timer);
          resolve(false);
        });

        proc.on("close", (code) => {
          clearTimeout(timer);
          resolve(code === 0);
        });
      } catch {
        resolve(false);
      }
    });
  }

  abstract buildArgs(targetPath: string, outputPath: string): string[];

  /**
   * Executes the tool against the targetPath, saving SARIF output to outputPath.
   */
  async run(options: ToolRunOptions): Promise<ToolRunOutput> {
    const startTime = Date.now();
    const resolvedBin = resolveExecutable(this.executable);

    if (!resolvedBin) {
      return {
        tool: this.name,
        status: "failed",
        exitCode: 127,
        durationSec: 0,
        error: `${this.name} is not installed or not found on PATH`,
        counts: { high: 0, medium: 0, low: 0 },
      };
    }

    const args = this.buildArgs(options.targetPath, options.outputPath);

    // Ensure output directory exists
    await fs.mkdir(path.dirname(options.outputPath), { recursive: true });

    return new Promise<ToolRunOutput>((resolve) => {
      let procError: string | undefined;

      const binDir = path.dirname(resolvedBin);
      const proc = spawn(resolvedBin, args, {
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          ...process.env,
          PYTHONUTF8: "1",
          PATH: `${binDir}${path.delimiter}${process.env.PATH || ""}`,
        },
      });

      let stderrOutput = "";
      proc.stderr?.on("data", (chunk) => {
        stderrOutput += chunk.toString();
      });

      let timeoutTimer: NodeJS.Timeout | undefined;
      if (options.timeoutMs && options.timeoutMs > 0) {
        timeoutTimer = setTimeout(() => {
          proc.kill("SIGTERM");
          const durationSec = Number(
            ((Date.now() - startTime) / 1000).toFixed(1),
          );
          resolve({
            tool: this.name,
            status: "failed",
            exitCode: 124,
            durationSec,
            error: `${this.name} timed out after ${options.timeoutMs}ms`,
            counts: { high: 0, medium: 0, low: 0 },
          });
        }, options.timeoutMs);
      }

      if (options.abortSignal) {
        options.abortSignal.addEventListener("abort", () => {
          proc.kill("SIGTERM");
        });
      }

      proc.on("error", (err) => {
        procError = err.message;
      });

      proc.on("close", async (exitCode) => {
        if (timeoutTimer) clearTimeout(timeoutTimer);

        const durationSec = Number(
          ((Date.now() - startTime) / 1000).toFixed(1),
        );
        const code = exitCode ?? 1;

        if (options.abortSignal?.aborted) {
          return resolve({
            tool: this.name,
            status: "failed",
            exitCode: code,
            durationSec,
            error: "Scan cancelled",
            counts: { high: 0, medium: 0, low: 0 },
          });
        }

        if (procError) {
          return resolve({
            tool: this.name,
            status: "failed",
            exitCode: code,
            durationSec,
            error: `${this.name} failed: ${procError}`,
            counts: { high: 0, medium: 0, low: 0 },
          });
        }

        // Try reading output SARIF file (even if exit code is non-zero, e.g. Gitleaks finding leaks)
        try {
          const sarifLog = await readSarifFile(options.outputPath);
          const counts: SeverityCounts = countFindings(sarifLog);

          resolve({
            tool: this.name,
            status: "done",
            exitCode: code,
            durationSec,
            sarifPath: options.outputPath,
            sarifLog,
            counts,
          });
        } catch {
          // If tool exited with non-zero and no valid SARIF was produced, report failure
          if (code !== 0) {
            resolve({
              tool: this.name,
              status: "failed",
              exitCode: code,
              durationSec,
              error:
                stderrOutput.trim() ||
                `${this.name} failed with exit code ${code}`,
              counts: { high: 0, medium: 0, low: 0 },
            });
          } else {
            // Clean exit code but no valid SARIF produced
            resolve({
              tool: this.name,
              status: "failed",
              exitCode: 0,
              durationSec,
              error: `Scanner finished with code 0 but produced no valid SARIF report at ${options.outputPath}`,
              counts: { high: 0, medium: 0, low: 0 },
            });
          }
        }
      });
    });
  }
}

/**
 * Runner for Trivy vulnerability & misconfiguration scanner.
 */
export class TrivyRunner extends BaseToolRunner {
  readonly name: ToolName = "trivy";
  readonly executable = process.env.TRIVY_PATH || "trivy";

  buildArgs(targetPath: string, outputPath: string): string[] {
    return ["fs", "--format", "sarif", "--output", outputPath, targetPath];
  }
}

/**
 * Runner for Semgrep static analysis / SAST scanner.
 */
export class SemgrepRunner extends BaseToolRunner {
  readonly name: ToolName = "semgrep";
  readonly executable = process.env.SEMGREP_PATH || "semgrep";

  buildArgs(targetPath: string, outputPath: string): string[] {
    return ["scan", "--sarif", "--output", outputPath, targetPath];
  }
}

/**
 * Runner for Gitleaks secret & credential detector.
 */
export class GitleaksRunner extends BaseToolRunner {
  readonly name: ToolName = "gitleaks";
  readonly executable = process.env.GITLEAKS_PATH || "gitleaks";

  buildArgs(targetPath: string, outputPath: string): string[] {
    return [
      "detect",
      "--source",
      targetPath,
      "--report-format",
      "sarif",
      "--report-path",
      outputPath,
    ];
  }
}

const RUNNERS: Record<ToolName, ToolRunner> = {
  trivy: new TrivyRunner(),
  semgrep: new SemgrepRunner(),
  gitleaks: new GitleaksRunner(),
};

/**
 * Retrieves the tool runner instance for a given tool.
 */
export function getToolRunner(tool: ToolName): ToolRunner {
  const runner = RUNNERS[tool];
  if (!runner) {
    throw new Error(`Unknown tool runner requested: ${tool}`);
  }
  return runner;
}

/**
 * Checks whether a given tool runner is available in the environment.
 */
export async function checkToolAvailability(tool: ToolName): Promise<boolean> {
  return getToolRunner(tool).isAvailable();
}
