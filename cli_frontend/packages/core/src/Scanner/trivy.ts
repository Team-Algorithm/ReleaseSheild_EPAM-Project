import { getToolRunner, checkToolAvailability } from "./tools.js";

import type { ToolRunOptions, ToolRunOutput } from "../types.js";

export async function isTrivyAvailable(): Promise<boolean> {
  return checkToolAvailability("trivy");
}

export function buildTrivyArgs(
  targetPath: string,
  outputPath: string,
): string[] {
  return getToolRunner("trivy").buildArgs(targetPath, outputPath);
}

export async function runTrivy(
  options: ToolRunOptions,
): Promise<ToolRunOutput> {
  if (!options.targetPath?.trim()) {
    return {
      tool: "trivy",
      status: "failed",
      exitCode: 1,
      durationSec: 0,
      counts: { high: 0, medium: 0, low: 0 },
      error: "A target repository path is required.",
    };
  }

  if (!options.outputPath?.trim()) {
    return {
      tool: "trivy",
      status: "failed",
      exitCode: 1,
      durationSec: 0,
      counts: { high: 0, medium: 0, low: 0 },
      error: "A SARIF output path is required.",
    };
  }

  return getToolRunner("trivy").run(options);
}
