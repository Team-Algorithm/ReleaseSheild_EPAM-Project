import type {
  SarifLog,
  SarifRun,
  ToolResult,
  SeverityCounts,
  ScanSummary,
} from "../types.js";
import { assertValidSarif, validateSarifDetailed } from "./validator.js";

export class SarifMergeError extends Error {
  readonly reportIndex?: number;
  readonly errors?: string[];

  constructor(message: string, reportIndex?: number, errors?: string[]) {
    super(message);
    this.name = "SarifMergeError";
    this.reportIndex = reportIndex;
    this.errors = errors;
  }
}

/**
 * Merges multiple validated SARIF 2.1.0 log documents into a single unified SARIF document.
 *
 * Rules:
 * - Every input report is strictly validated against the official OASIS SARIF 2.1.0 schema.
 * - Never silently discards an invalid or malformed report; throws SarifMergeError on failure.
 * - Preserves all valid runs from each tool report.
 * - Validates the final merged document before returning.
 *
 * @throws {SarifMergeError} if any input report or the merged output fails schema validation.
 */
export function mergeSarif(sarifLogs: SarifLog[]): SarifLog {
  if (!Array.isArray(sarifLogs)) {
    throw new SarifMergeError("Input to mergeSarif must be an array of SarifLog documents.");
  }

  const combinedRuns: SarifRun[] = [];

  for (let i = 0; i < sarifLogs.length; i++) {
    const log = sarifLogs[i];
    const validation = validateSarifDetailed(log);

    if (!validation.valid) {
      const errorSummaries = validation.errors
        .slice(0, 3)
        .map((e) => `${e.path ? e.path + ": " : ""}${e.message}`);
      throw new SarifMergeError(
        `Cannot merge invalid SARIF document at index ${i}: ${errorSummaries.join("; ")}`,
        i,
        errorSummaries
      );
    }

    combinedRuns.push(...log.runs);
  }

  const mergedDocument: SarifLog = {
    version: "2.1.0",
    $schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
    runs: combinedRuns,
  };

  // Validate the final merged output to guarantee specification compliance
  assertValidSarif(mergedDocument);

  return mergedDocument;
}

/**
 * Builds a standardized ScanSummary from tool results.
 *
 * Calculates total vulnerability counts across all tools and computes
 * totalDurationSec as the maximum wall-clock duration of parallel scanner executions.
 */
export function buildSummary(
  toolResults: ToolResult[],
  savedPath = "./results/result.sarif"
): ScanSummary {
  const totalCounts: SeverityCounts = toolResults.reduce(
    (acc, cur) => ({
      high: acc.high + cur.counts.high,
      medium: acc.medium + cur.counts.medium,
      low: acc.low + cur.counts.low,
    }),
    { high: 0, medium: 0, low: 0 }
  );

  const totalDurationSec = toolResults.reduce(
    (max, cur) => Math.max(max, cur.durationSec),
    0
  );

  return {
    tools: toolResults,
    totalCounts,
    totalDurationSec,
    savedPath,
  };
}

