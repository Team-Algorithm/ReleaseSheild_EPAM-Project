import { getToolRunner, checkToolAvailability } from "../tools.js";
import type { ToolRunOptions, ToolRunOutput } from "../types.js";

/**
 * Checks whether Semgrep CLI is installed and accessible on PATH.
 */
export async function isSemgrepAvailable(): Promise<boolean> {
  return checkToolAvailability("semgrep");
}

/**
 * Builds standard CLI arguments for Semgrep SARIF scanning.
 */
export function buildSemgrepArgs(
  targetPath: string,
  outputPath: string,
): string[] {
  return getToolRunner("semgrep").buildArgs(targetPath, outputPath);
}

/**
 * Executes Semgrep scanner against the target repository path.
 */
export async function runSemgrep(
  options: ToolRunOptions,
): Promise<ToolRunOutput> {
  if (!options.targetPath?.trim()) {
    return {
      tool: "semgrep",
      status: "failed",
      exitCode: 1,
      durationSec: 0,
      counts: { high: 0, medium: 0, low: 0 },
      error: "A target repository path is required.",
    };
  }

  if (!options.outputPath?.trim()) {
    return {
      tool: "semgrep",
      status: "failed",
      exitCode: 1,
      durationSec: 0,
      counts: { high: 0, medium: 0, low: 0 },
      error: "A SARIF output path is required.",
    };
  }

  return getToolRunner("semgrep").run(options);
}

