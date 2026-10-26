import * as fs from 'fs/promises';
import * as path from 'path';
import type {
  SarifLog,
  SarifRun,
  SarifResult,
  Severity,
  SeverityCounts,
  Finding,
  ToolName,
  ToolResult,
  ScanSummary
} from './types.js';

/**
 * Validates that an object conforms to minimal SARIF 2.1.0 specifications.
 */
export function validateSarif(sarif: unknown): sarif is SarifLog {
  if (typeof sarif !== 'object' || sarif === null) {
    return false;
  }

  const s = sarif as Partial<SarifLog>;
  if (s.version !== '2.1.0') {
    return false;
  }

  if (!Array.isArray(s.runs)) {
    return false;
  }

  for (const run of s.runs) {
    if (!run || typeof run !== 'object') {
      return false;
    }
    if (!run.tool || typeof run.tool !== 'object' || !run.tool.driver || typeof run.tool.driver.name !== 'string') {
      return false;
    }
    if (run.results !== undefined && !Array.isArray(run.results)) {
      return false;
    }
  }

  return true;
}

/**
 * Parses a raw JSON string into a validated SarifLog structure.
 */
export function parseSarif(jsonString: string): SarifLog {
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonString);
  } catch (err) {
    throw new Error(`Failed to parse SARIF JSON: ${err instanceof Error ? err.message : String(err)}`);
  }

  if (!validateSarif(parsed)) {
    throw new Error('Invalid SARIF 2.1.0 structure: missing version 2.1.0 or valid runs array');
  }

  return parsed;
}

/**
 * Normalizes SARIF result level and security-severity scores into standardized high, medium, or low severity.
 */
export function sarifLevelToSeverity(level?: string, securitySeverity?: string | number): Severity {
  // If CVSS / security-severity score is provided (numeric or numeric string)
  if (securitySeverity !== undefined && securitySeverity !== null) {
    const score = typeof securitySeverity === 'number' ? securitySeverity : parseFloat(String(securitySeverity));
    if (!Number.isNaN(score)) {
      if (score >= 7.0) return 'high';
      if (score >= 4.0) return 'medium';
      return 'low';
    }
  }

  const l = (level || 'warning').toLowerCase();
  if (l === 'error') {
    return 'high';
  }
  if (l === 'warning') {
    return 'medium';
  }
  if (l === 'note' || l === 'none') {
    return 'low';
  }

  return 'medium';
}

/**
 * Counts findings by severity (high, medium, low) from a SarifLog or single SarifRun.
 */
export function countFindings(sarif: SarifLog | SarifRun): SeverityCounts {
  const counts: SeverityCounts = { high: 0, medium: 0, low: 0 };
  const runs: SarifRun[] = 'runs' in sarif ? sarif.runs : [sarif];

  for (const run of runs) {
    if (!run.results) continue;

    // Build rule map to check default rule level or security-severity if available
    const ruleMap = new Map<string, { level?: string; securitySeverity?: string | number }>();
    if (run.tool?.driver?.rules) {
      for (const rule of run.tool.driver.rules) {
        ruleMap.set(rule.id, {
          level: rule.defaultConfiguration?.level,
          securitySeverity: rule.properties?.['security-severity']
        });
      }
    }

    for (const res of run.results) {
      const ruleInfo = res.ruleId ? ruleMap.get(res.ruleId) : undefined;
      const secSev = res.properties?.['security-severity'] ?? ruleInfo?.securitySeverity;
      const level = res.level ?? ruleInfo?.level;
      const severity = sarifLevelToSeverity(level, secSev);

      counts[severity]++;
    }
  }

  return counts;
}

/**
 * Normalizes a driver name to a known ToolName.
 */
function normalizeToolName(driverName: string): ToolName {
  const lower = driverName.toLowerCase();
  if (lower.includes('semgrep')) return 'semgrep';
  if (lower.includes('gitleaks')) return 'gitleaks';
  return 'trivy';
}

/**
 * Extracts and maps raw SARIF findings into the normalized Finding[] model used by CLI and UI.
 */
export function extractFindings(sarif: SarifLog, toolFilter?: ToolName): Finding[] {
  const findings: Finding[] = [];

  for (const run of sarif.runs) {
    const rawToolName = run.tool?.driver?.name || 'unknown';
    const tool = normalizeToolName(rawToolName);

    if (toolFilter && tool !== toolFilter) {
      continue;
    }

    const ruleMap = new Map<string, { level?: string; securitySeverity?: string | number }>();
    if (run.tool?.driver?.rules) {
      for (const rule of run.tool.driver.rules) {
        ruleMap.set(rule.id, {
          level: rule.defaultConfiguration?.level,
          securitySeverity: rule.properties?.['security-severity']
        });
      }
    }

    if (!run.results) continue;

    for (const res of run.results) {
      const ruleId = res.ruleId || 'security-finding';
      const ruleInfo = ruleMap.get(ruleId);
      const secSev = res.properties?.['security-severity'] ?? ruleInfo?.securitySeverity;
      const level = res.level ?? ruleInfo?.level;
      const severity = sarifLevelToSeverity(level, secSev);

      const physLoc = res.locations?.[0]?.physicalLocation;
      const location = physLoc?.artifactLocation?.uri || 'unknown';
      const line = physLoc?.region?.startLine;
      const message = res.message?.text || 'No description provided';

      findings.push({
        tool,
        rule: ruleId,
        severity,
        location,
        line,
        message
      });
    }
  }

  return findings;
}

/**
 * Merges multiple SARIF log documents into a single unified SARIF 2.1.0 document.
 */
export function mergeSarif(sarifLogs: SarifLog[]): SarifLog {
  const validLogs = sarifLogs.filter(validateSarif);
  const combinedRuns: SarifRun[] = [];

  for (const log of validLogs) {
    combinedRuns.push(...log.runs);
  }

  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: combinedRuns
  };
}

/**
 * Builds a standardized ScanSummary from tool results.
 */
export function buildSummary(
  toolResults: ToolResult[],
  savedPath = './results/result.sarif'
): ScanSummary {
  const totalCounts: SeverityCounts = toolResults.reduce(
    (acc, cur) => ({
      high: acc.high + cur.counts.high,
      medium: acc.medium + cur.counts.medium,
      low: acc.low + cur.counts.low
    }),
    { high: 0, medium: 0, low: 0 }
  );

  const totalDurationSec = toolResults.reduce((max, cur) => Math.max(max, cur.durationSec), 0);

  return {
    tools: toolResults,
    totalCounts,
    totalDurationSec,
    savedPath
  };
}

/**
 * Reads and validates a SARIF file from the filesystem.
 */
export async function readSarifFile(filePath: string): Promise<SarifLog> {
  const content = await fs.readFile(filePath, 'utf-8');
  return parseSarif(content);
}

/**
 * Writes a SARIF document to the filesystem, creating any missing parent directories.
 */
export async function writeSarifFile(filePath: string, sarif: SarifLog): Promise<void> {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });
  const jsonContent = JSON.stringify(sarif, null, 2);
  await fs.writeFile(filePath, jsonContent, 'utf-8');
}
