import type {
  SarifLog,
  SarifRun,
  SarifResult,
  Severity,
  SeverityCounts,
  Finding,
  ToolName,
} from "../types.js";

export class SarifExtractionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SarifExtractionError";
  }
}

/**
 * Normalizes SARIF result level and security-severity scores into standardized high, medium, or low severity.
 *
 * Thresholds:
 * - Score >= 7.0 -> "high"
 * - Score >= 4.0 and < 7.0 -> "medium"
 * - Score < 4.0 -> "low"
 *
 * Fallback levels:
 * - "error" -> "high"
 * - "warning" -> "medium"
 * - "note" | "none" -> "low"
 * - Default -> "medium"
 */
export function sarifLevelToSeverity(
  level?: string,
  securitySeverity?: string | number
): Severity {
  if (securitySeverity !== undefined && securitySeverity !== null) {
    const score =
      typeof securitySeverity === "number"
        ? securitySeverity
        : parseFloat(String(securitySeverity));
    if (!Number.isNaN(score)) {
      if (score >= 7.0) return "high";
      if (score >= 4.0) return "medium";
      return "low";
    }
  }

  const l = (level || "warning").toLowerCase();
  if (l === "error") {
    return "high";
  }
  if (l === "warning") {
    return "medium";
  }
  if (l === "note" || l === "none") {
    return "low";
  }

  return "medium";
}

export interface RuleMetadata {
  level?: string;
  securitySeverity?: string | number;
  shortDescription?: string;
  fullDescription?: string;
}

/**
 * Builds an index map of rule IDs to their configurations and properties from a SarifRun.
 */
function buildRuleMap(run: SarifRun): Map<string, RuleMetadata> {
  const map = new Map<string, RuleMetadata>();
  if (run.tool?.driver?.rules) {
    for (const rule of run.tool.driver.rules) {
      map.set(rule.id, {
        level: rule.defaultConfiguration?.level,
        securitySeverity: rule.properties?.["security-severity"],
        shortDescription: rule.shortDescription?.text,
        fullDescription: rule.fullDescription?.text,
      });
    }
  }
  return map;
}

/**
 * Shared helper that resolves the effective severity for a SarifResult.
 * Ensures countFindings and extractFindings use strictly identical resolution logic.
 */
function resolveResultSeverity(
  res: SarifResult,
  ruleMap: Map<string, RuleMetadata>
): Severity {
  const ruleInfo = res.ruleId ? ruleMap.get(res.ruleId) : undefined;
  const secSev =
    res.properties?.["security-severity"] ?? ruleInfo?.securitySeverity;
  const level = res.level ?? ruleInfo?.level;
  return sarifLevelToSeverity(level, secSev);
}

/**
 * Normalizes a SARIF driver name into a known ToolName.
 * Returns undefined for unrecognized tools (never silently defaults to Trivy).
 */
export function normalizeToolName(driverName: string): ToolName | undefined {
  const lower = driverName.toLowerCase();
  if (lower.includes("trivy")) return "trivy";
  if (lower.includes("gitleaks")) return "gitleaks";
  if (lower.includes("semgrep")) return "semgrep";
  return undefined;
}

/**
 * Counts findings by severity (high, medium, low) across all runs in a SarifLog or single SarifRun.
 */
export function countFindings(sarif: SarifLog | SarifRun): SeverityCounts {
  const counts: SeverityCounts = { high: 0, medium: 0, low: 0 };
  const runs: SarifRun[] = "runs" in sarif ? sarif.runs : [sarif];

  for (const run of runs) {
    if (!run.results) continue;

    const ruleMap = buildRuleMap(run);

    for (const res of run.results) {
      const severity = resolveResultSeverity(res, ruleMap);
      counts[severity]++;
    }
  }

  return counts;
}

/**
 * Extracts and maps raw SARIF results into the normalized Finding[] model used by CLI and UI.
 *
 * @throws {SarifExtractionError} if an unrecognized scanner driver is encountered.
 */
export function extractFindings(
  sarif: SarifLog,
  toolFilter?: ToolName
): Finding[] {
  const findings: Finding[] = [];

  for (const run of sarif.runs) {
    const rawDriverName = run.tool?.driver?.name || "unknown";
    const tool = normalizeToolName(rawDriverName);

    if (!tool) {
      throw new SarifExtractionError(
        `Unsupported tool driver "${rawDriverName}" in SARIF report. Expected one of: trivy, gitleaks, semgrep.`
      );
    }

    if (toolFilter && tool !== toolFilter) {
      continue;
    }

    const ruleMap = buildRuleMap(run);

    if (!run.results) continue;

    for (const res of run.results) {
      const ruleId = res.ruleId || "security-finding";
      const ruleInfo = ruleMap.get(ruleId);
      const severity = resolveResultSeverity(res, ruleMap);

      const physLoc = res.locations?.[0]?.physicalLocation;
      const location = physLoc?.artifactLocation?.uri || "unknown";
      const line = physLoc?.region?.startLine;
      const message =
        res.message?.text ||
        ruleInfo?.shortDescription ||
        ruleInfo?.fullDescription ||
        "No description provided";

      findings.push({
        tool,
        rule: ruleId,
        severity,
        location,
        line,
        message,
      });
    }
  }

  return findings;
}

