import fs from "node:fs";
import path from "node:path";
import { validateSarif } from "./validator.js";
import type { SarifLog } from "./types.js";

export interface MergeOptions {
  schemaPath?: string;
  outputPath?: string;
}

/**
 * Validate every input first, then combine all SARIF runs into one SARIF 2.1.0 log.
 * Top-level metadata is based on the first input; runs from all reports are preserved.
 */
export function mergeSarifFiles(
  inputPaths: string[],
  options: MergeOptions = {},
): SarifLog {
  if (inputPaths.length === 0) {
    throw new Error("Provide at least one SARIF input file.");
  }

  const reports = inputPaths.map((file) =>
    validateSarif(file, options.schemaPath),
  );
  const first = reports[0];

  const merged: SarifLog = {
    ...first,
    version: "2.1.0",
    runs: reports.flatMap((report) => report.runs),
  };

  if (options.outputPath) {
    const output = path.resolve(options.outputPath);
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, `${JSON.stringify(merged, null, 2)}\n`, "utf8");
  }
  return merged;
}
