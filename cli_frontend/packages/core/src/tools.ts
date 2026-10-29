import { spawn } from "child_process";
import * as path from "path";
import * as fs from "fs/promises";
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
 * Base abstract class for security scanner tool runners.
 */
export abstract class BaseToolRunner implements ToolRunner {
  abstract readonly name: ToolName;
  abstract readonly executable: string;

  /**
   * Checks whether the tool CLI is installed and accessible on PATH.
   */
  async isAvailable(): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      try {
        const proc = spawn(this.executable, ["--version"], {
          shell: true,
          stdio: "ignore",
        });
        proc.on("error", () => resolve(false));
        proc.on("close", (code) => resolve(code === 0));
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

    // Ensure output directory exists
    await fs.mkdir(path.dirname(options.outputPath), { recursive: true });

    return new Promise<ToolRunOutput>((resolve) => {
      let procError: string | undefined;

      const proc = spawn(this.executable, args, {
        shell: true,
        stdio: ["ignore", "pipe", "pipe"],
      });

      let stderrOutput = "";
      proc.stderr?.on("data", (chunk) => {
        stderrOutput += chunk.toString();
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
            error: `${this.name} not found`,
            counts: { high: 0, medium: 0, low: 0 },
          });
        }

        // Try reading output SARIF file
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
          // If tool exited with non-zero and no SARIF produced, report failure
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
            // Clean exit but no findings SARIF
            resolve({
              tool: this.name,
              status: "done",
              exitCode: 0,
              durationSec,
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
    return [
      "fs",
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
  readonly executable = "semgrep";

  buildArgs(targetPath: string, outputPath: string): string[] {
    return ["scan", "--sarif", "--output", outputPath, targetPath];
  }
}

/**
 * Runner for Gitleaks secret & credential detector.
 */
export class GitleaksRunner extends BaseToolRunner {
  readonly name: ToolName = "gitleaks";
  readonly executable = "gitleaks";

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
