import { getToolRunner, checkToolAvailability } from "../tools.js";

import type { ToolRunOptions, ToolRunOutput } from "../types.js";

/**
 * Checks whether the Gitleaks binary is installed and reachable.
 */
export async function isGitleaksAvailable(): Promise<boolean> {
  return checkToolAvailability("gitleaks");
}
/**
 * Builds the CLI argument list for Gitleaks by delegating to the registered runner.
 */
export function buildGitleaksArgs(
  targetPath: string,
  outputPath: string,
): string[] {
  return getToolRunner("gitleaks").buildArgs(targetPath, outputPath);
}
/**
 * Executes Gitleaks using the common tool runner.
 * Mirrors the validation logic used by the Trivy wrapper.
 */
export async function runGitleaks(
  options: ToolRunOptions,
): Promise<ToolRunOutput> {
  if (!options.targetPath?.trim()) {
    return {
      tool: "gitleaks",
      status: "failed",
      exitCode: 1,
      durationSec: 0,
      counts: { high: 0, medium: 0, low: 0 },
      error: "A target repository path is required.",
    };
  }
  if (!options.outputPath?.trim()) {
    return {
      tool: "gitleaks",
      status: "failed",
      exitCode: 1,
      durationSec: 0,
      counts: { high: 0, medium: 0, low: 0 },
      error: "A SARIF output path is required.",
    };
  }
  return getToolRunner("gitleaks").run(options);
}
