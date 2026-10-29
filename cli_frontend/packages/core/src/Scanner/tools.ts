import { spawn } from "child_process";
import * as path from "path";
import * as fsSync from "fs";
import * as fs from "fs/promises";
import type {
  ToolName,
  ToolStatus,
  ToolRunner,
  ToolRunOptions,
  ToolRunOutput,
  SeverityCounts,
} from "../types.js";
import { readSarifFile, countFindings } from "../sarif/index.js";

/**
 * Builds an augmented environment for scanner subprocesses.
 * - Forces UTF-8 encoding on Windows to prevent Python charmap/UnicodeEncodeErrors
 * - Ensures standard Windows Python Scripts directory is reachable on PATH
 */
export function getAugmentedEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PYTHONIOENCODING: "utf-8",
    PYTHONUTF8: "1",
  };

  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA || "";
    const candidateDirs = [
      path.join(localAppData, "Programs", "Python", "Python313", "Scripts"),
      path.join(
        localAppData,
        "Microsoft",
        "WinGet",
        "Packages",
        "AquaSecurity.Trivy_Microsoft.Winget.Source_8wekyb3d8bbwe"
      ),
      path.join(
        localAppData,
        "Microsoft",
        "WinGet",
        "Packages",
        "Gitleaks.Gitleaks_Microsoft.Winget.Source_8wekyb3d8bbwe"
      ),
      path.join(localAppData, "Microsoft", "WinGet", "Links"),
    ];

    const pathKey =
      Object.keys(env).find((k) => k.toLowerCase() === "path") || "PATH";
    let currentPath = env[pathKey] || "";

    for (const candidate of candidateDirs) {
      if (candidate && !currentPath.includes(candidate) && fsSync.existsSync(candidate)) {
        currentPath = `${candidate};${currentPath}`;
      }
    }
    env[pathKey] = currentPath;
  }

  return env;
}

/**
 * Base abstract class for security scanner tool runners.
 */
export abstract class BaseToolRunner implements ToolRunner {
  abstract readonly name: ToolName;
  abstract readonly executable: string;
  spawnFn: typeof spawn = spawn;

  /**
   * Checks whether the tool CLI is installed and accessible on PATH.
   */
  async isAvailable(): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      try {
        const proc = this.spawnFn(this.executable, ["--version"], {
          shell: true,
          stdio: "ignore",
          env: getAugmentedEnv(),
        });
        proc.on("error", () => resolve(false));
        proc.on("close", (code: number | null) => resolve(code === 0));
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
    const args = this.buildArgs(options.targetPath, options.outputPath);

    // Prevent old report from being mistaken for current run output
    await fs.rm(options.outputPath, { force: true });
    // Ensure output directory exists
    await fs.mkdir(path.dirname(options.outputPath), { recursive: true });

    return new Promise<ToolRunOutput>((resolve) => {
      let procError: string | undefined;
      let timedOut = false;
      let timeoutId: NodeJS.Timeout | undefined;

      const proc = this.spawnFn(this.executable, args, {
        shell: true,
        stdio: ["ignore", "pipe", "pipe"],
        env: getAugmentedEnv(),
      });

      if (options.timeoutMs && options.timeoutMs > 0) {
        timeoutId = setTimeout(() => {
          timedOut = true;
          proc.kill("SIGTERM");
        }, options.timeoutMs);
      }

      let stderrOutput = "";
      proc.stderr?.on("data", (chunk) => {
        if (stderrOutput.length < 8192) {
          stderrOutput += chunk.toString();
        }
      });

      let stdoutOutput = "";
      proc.stdout?.on("data", (chunk) => {
        if (stdoutOutput.length < 8192) {
          stdoutOutput += chunk.toString();
        }
      });

      if (options.abortSignal) {
        options.abortSignal.addEventListener("abort", () => {
          proc.kill("SIGTERM");
        });
      }

      proc.on("error", (err) => {
        procError = err.message;
      });

      proc.on("close", async (exitCode) => {
        if (timeoutId) {
          clearTimeout(timeoutId);
        }

        const durationSec = Number(
          ((Date.now() - startTime) / 1000).toFixed(1)
        );
        const code = exitCode ?? 1;

        if (timedOut) {
          await fs.rm(options.outputPath, { force: true });
          return resolve({
            tool: this.name,
            status: "failed",
            exitCode: code,
            durationSec,
            error: `Scan timed out after ${options.timeoutMs}ms`,
            counts: { high: 0, medium: 0, low: 0 },
          });
        }

        if (options.abortSignal?.aborted) {
          await fs.rm(options.outputPath, { force: true });
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
          await fs.rm(options.outputPath, { force: true });
          return resolve({
            tool: this.name,
            status: "failed",
            exitCode: code,
            durationSec,
            error: `${this.name} not found`,
            counts: { high: 0, medium: 0, low: 0 },
          });
        }

        // Semgrep and Gitleaks return exit code 1 when findings are present; exit >= 2 represents execution errors.
        // Trivy returns 0 on successful scan; non-zero represents errors.
        const isAcceptableExitCode =
          code === 0 ||
          ((this.name === "semgrep" || this.name === "gitleaks") && code === 1);

        if (!isAcceptableExitCode) {
          await fs.rm(options.outputPath, { force: true });
          const diag = stderrOutput.trim() || stdoutOutput.trim();
          const error = diag
            ? `${this.name} failed (exit ${code}): ${diag}`
            : `${this.name} exited with error code ${code}`;

          return resolve({
            tool: this.name,
            status: "failed",
            exitCode: code,
            durationSec,
            error,
            counts: { high: 0, medium: 0, low: 0 },
          });
        }

        // Try reading and validating output SARIF file
        try {
          const sarifLog = await readSarifFile(options.outputPath);
          const counts: SeverityCounts = countFindings(sarifLog);
          const hasIssues =
            counts.high > 0 || counts.medium > 0 || counts.low > 0;
          const status: ToolStatus = hasIssues ? "done" : "done";

          resolve({
            tool: this.name,
            status,
            exitCode: code,
            durationSec,
            sarifPath: options.outputPath,
            sarifLog,
            counts,
          });
        } catch (sarifErr) {
          // Never report missing or invalid SARIF as a clean scan!
          await fs.rm(options.outputPath, { force: true });
          const diag = stderrOutput.trim() || stdoutOutput.trim();
          const sarifMsg =
            sarifErr instanceof Error ? sarifErr.message : String(sarifErr);
          const error = diag
            ? `${this.name} failed (exit ${code}): ${diag}`
            : `${this.name} exited with code ${code} without producing a valid SARIF report (${sarifMsg})`;

          resolve({
            tool: this.name,
            status: "failed",
            exitCode: code,
            durationSec,
            error,
            counts: { high: 0, medium: 0, low: 0 },
          });
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
    return [
      "fs",
      "--scanners",
      "vuln",
      "--format",
      "sarif",
      "--output",
      outputPath,
      targetPath,
    ];
  }
}

/**
 * Runner for Semgrep static analysis / SAST scanner.
 */
export class SemgrepRunner extends BaseToolRunner {
  readonly name: ToolName = "semgrep";
  readonly executable = process.env.SEMGREP_PATH || "semgrep";

  buildArgs(targetPath: string, outputPath: string): string[] {
    return [
      "scan",
      "--config",
      "p/default",
      "--sarif",
      "--output",
      outputPath,
      "--metrics=off",
      "--disable-version-check",
      targetPath,
    ];
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
