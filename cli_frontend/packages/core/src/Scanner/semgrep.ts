import { getToolRunner, checkToolAvailability } from "./tools.js";

import type { ToolRunOptions, ToolRunOutput } from "../types.js";

/**
 * Checks whether the Semgrep binary is installed and reachable.
 */
export async function isSemgrepAvailable(): Promise<boolean> {
  return checkToolAvailability("semgrep");
}

/**
 * Builds the CLI argument list for Semgrep by delegating to the registered runner.
 */
export function buildSemgrepArgs(
  targetPath: string,
  outputPath: string,
): string[] {
  return getToolRunner("semgrep").buildArgs(targetPath, outputPath);
}

/**
 * Executes Semgrep using the common tool runner.
 * Mirrors the validation logic used by Trivy and Gitleaks wrappers.
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
