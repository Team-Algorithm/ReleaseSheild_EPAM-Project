import { getToolRunner, checkToolAvailability } from "../tools.js";
import type { ToolRunOptions, ToolRunOutput } from "../types.js";

/**
 * Checks whether Gitleaks CLI is installed and accessible on PATH.
 */
export async function isGitleaksAvailable(): Promise<boolean> {
  return checkToolAvailability("gitleaks");
}

/**
 * Builds standard CLI arguments for Gitleaks SARIF detection.
 */
export function buildGitleaksArgs(
  targetPath: string,
  outputPath: string,
): string[] {
  return getToolRunner("gitleaks").buildArgs(targetPath, outputPath);
}

/**
 * Executes Gitleaks secret scanner against the target repository path.
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

