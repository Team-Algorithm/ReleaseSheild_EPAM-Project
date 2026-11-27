import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";

export const DEFAULT_RESULT_SARIF_PATH = "./packages/core/results/result.sarif";
export const DEFAULT_NORMALIZED_OUTPUT_PATH =
  "./packages/core/results/normalized-findings.json";

/** Matches security.issues.severity CHECK constraint. */
export type NormalizedSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "unknown";

/** Matches security.issue_occurrences.scanner CHECK constraint. */
export type NormalizedScanner = "trivy" | "semgrep" | "gitleaks";

/** Structured JSONB payload for security.issue_occurrences.evidence. */
export interface FindingEvidence {
  message: string;
  snippet?: string;
  driverName?: string;
  normalizedTitle?: string;
  helpUri?: string;
  tags?: string[];
  properties?: Record<string, unknown>;
  fingerprints?: Record<string, string>;
}

/**
 * Normalized finding aligned with Sprint 2 PostgreSQL tables:
 * - security.issues (repoId/repository context, title, severity)
 * - security.issue_occurrences (scanner, ruleId, filePath, startLine, endLine,
 *   startColumn, endColumn, severity, codeFingerprint, evidence)
 */
export interface NormalizedFinding {
  repoId: string;
  scanner: NormalizedScanner;
  ruleId: string | null;
  title: string;
  normalizedTitle: string;
  severity: NormalizedSeverity;
  filePath: string;
  startLine: number | null;
  endLine: number | null;
  startColumn: number | null;
  endColumn: number | null;
  codeFingerprint: string | null;
  evidence: FindingEvidence;
}

export interface NormalizeSarifOptions {
  /** Explicit repository name/identifier; inferred from SARIF originalUriBaseIds if omitted. */
  repoId?: string;
  /** Optional repository root path to strip when computing repository-relative filePath values. */
  repoRoot?: string;
}

export interface NormalizableSarifMessage {
  text?: string;
  markdown?: string;
}

export interface NormalizableSarifRule {
  id?: string;
  name?: string;
  shortDescription?: NormalizableSarifMessage;
  fullDescription?: NormalizableSarifMessage;
  helpUri?: string;
  defaultConfiguration?: {
    level?: string;
  };
  properties?: Record<string, unknown>;
}

export interface NormalizableSarifLocation {
  physicalLocation?: {
    artifactLocation?: {
      uri?: string;
      uriBaseId?: string;
    };
    region?: {
      startLine?: number;
      endLine?: number;
      startColumn?: number;
      endColumn?: number;
      snippet?: {
        text?: string;
      };
    };
  };
}

export interface NormalizableSarifResult {
  ruleId?: string;
  ruleIndex?: number;
  rule?: {
    id?: string;
    index?: number;
  };
  level?: string;
  message?: NormalizableSarifMessage;
  locations?: NormalizableSarifLocation[];
  fingerprints?: Record<string, string>;
  partialFingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
}

export interface NormalizableSarifRun {
  tool?: {
    driver?: {
      name?: string;
      fullName?: string;
      rules?: NormalizableSarifRule[];
    };
  };
  results?: NormalizableSarifResult[];
  originalUriBaseIds?: Record<string, { uri?: string }>;
}

export interface NormalizableSarifLog {
  $schema?: string;
  version?: string;
  runs?: NormalizableSarifRun[] | null;
}

const LEVEL_TO_SEVERITY: Record<string, NormalizedSeverity> = {
  error: "high",
  warning: "medium",
  note: "low",
  none: "info",
};

const VALID_SEVERITIES = new Set<NormalizedSeverity>([
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "unknown",
]);

/** Convert a finding title into a lowercase hyphenated slug. */
export function normalizeTitle(title: string): string {
  return title
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/** Map raw SARIF driver name to DB-constrained scanner enum ('trivy' | 'semgrep' | 'gitleaks'). */
export function normalizeScanner(driverName: string): NormalizedScanner {
  const lower = driverName.toLowerCase();
  if (lower.includes("trivy")) return "trivy";
  if (lower.includes("semgrep")) return "semgrep";
  if (lower.includes("gitleaks")) return "gitleaks";
  throw new Error(
    `Unsupported scanner driver "${driverName}" in SARIF report. Expected one of: trivy, semgrep, gitleaks.`
  );
}

function toPosix(p: string): string {
  return p.replace(/^file:\/+/i, "").replace(/\\/g, "/");
}

function extractRepoNameFromUri(uri: string): string | undefined {
  const cleaned = toPosix(uri).replace(/\/+$/, "");
  if (!cleaned) return undefined;
  const name = basename(cleaned);
  return name || undefined;
}

function collectBaseRoots(
  sarif: NormalizableSarifLog,
  explicitRoot?: string
): string[] {
  const roots: string[] = [];
  if (explicitRoot) {
    roots.push(toPosix(explicitRoot).replace(/\/+$/, ""));
  }
  for (const run of sarif.runs ?? []) {
    for (const entry of Object.values(run.originalUriBaseIds ?? {})) {
      if (entry?.uri) {
        roots.push(toPosix(entry.uri).replace(/\/+$/, ""));
      }
    }
  }
  return roots;
}

function resolveRunRepoId(run: NormalizableSarifRun): string | undefined {
  const baseIds = run.originalUriBaseIds;
  if (!baseIds) return undefined;

  const preferred =
    baseIds["ROOTPATH"] ?? baseIds["%SRCROOT%"] ?? Object.values(baseIds)[0];
  return preferred?.uri ? extractRepoNameFromUri(preferred.uri) : undefined;
}

function resolveLogRepoId(
  sarif: NormalizableSarifLog,
  options: NormalizeSarifOptions
): string {
  if (options.repoId) return options.repoId;
  if (options.repoRoot) {
    const fromRoot = extractRepoNameFromUri(options.repoRoot);
    if (fromRoot) return fromRoot;
  }
  for (const run of sarif.runs ?? []) {
    const fromRun = resolveRunRepoId(run);
    if (fromRun) return fromRun;
  }
  return "unknown-repo";
}

/**
 * Convert raw SARIF artifactLocation.uri into a repository-relative POSIX path
 * suitable for CODEOWNERS matching (security.issue_occurrences.file_path).
 */
export function toRepoRelativePath(
  rawUri: string | undefined,
  repoRoots: string[],
  repoId?: string
): string {
  if (!rawUri || !rawUri.trim()) return "unknown";

  let normalized = toPosix(rawUri.trim());

  for (const root of repoRoots) {
    if (!root) continue;
    const prefix = `${root}/`;
    if (normalized.toLowerCase().startsWith(prefix.toLowerCase())) {
      normalized = normalized.slice(prefix.length);
      break;
    }
  }

  // Fallback: if path still contains Windows/Unix drive prefix with "/<repoId>/", strip up to repoId
  if (repoId && repoId !== "unknown-repo" && (/^[a-z]:\//i.test(normalized) || normalized.startsWith("/"))) {
    const marker = `/${repoId}/`;
    const idx = normalized.toLowerCase().indexOf(marker.toLowerCase());
    if (idx >= 0) {
      normalized = normalized.slice(idx + marker.length);
    }
  }

  normalized = normalized.replace(/^\.\//, "").replace(/^\/+/, "");
  return normalized || "unknown";
}

function toPositiveIntOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value > 0
    ? value
    : null;
}

interface RuleLookup {
  rules: NormalizableSarifRule[];
  byId: Map<string, NormalizableSarifRule>;
}

function createRuleLookup(run: NormalizableSarifRun): RuleLookup {
  const rules = run.tool?.driver?.rules ?? [];
  const byId = new Map<string, NormalizableSarifRule>();
  for (const rule of rules) {
    if (rule.id) byId.set(rule.id, rule);
  }
  return { rules, byId };
}

function findMatchingRule(
  lookup: RuleLookup,
  result: NormalizableSarifResult
): NormalizableSarifRule | undefined {
  const ruleIndex = result.ruleIndex ?? result.rule?.index;
  if (typeof ruleIndex === "number" && lookup.rules[ruleIndex]) {
    return lookup.rules[ruleIndex];
  }

  const ruleId = result.ruleId ?? result.rule?.id;
  return ruleId ? lookup.byId.get(ruleId) : undefined;
}

function mapNumericSecuritySeverity(score: number): NormalizedSeverity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "info";
}

function resolveSeverity(
  result: NormalizableSarifResult,
  rule: NormalizableSarifRule | undefined,
  scanner: NormalizedScanner
): NormalizedSeverity {
  const propSeverity =
    result.properties?.["severity"] ?? rule?.properties?.["severity"];
  if (typeof propSeverity === "string") {
    const lower = propSeverity.trim().toLowerCase() as NormalizedSeverity;
    if (VALID_SEVERITIES.has(lower)) return lower;
  }

  const rawScore =
    result.properties?.["security-severity"] ??
    rule?.properties?.["security-severity"];
  if (rawScore !== undefined && rawScore !== null) {
    const numeric = typeof rawScore === "number" ? rawScore : Number(rawScore);
    if (!Number.isNaN(numeric)) return mapNumericSecuritySeverity(numeric);
  }

  const level = (
    result.level ?? rule?.defaultConfiguration?.level
  )?.toLowerCase();
  if (level && LEVEL_TO_SEVERITY[level]) {
    return LEVEL_TO_SEVERITY[level];
  }

  if (scanner === "gitleaks") {
    return "high";
  }

  return "unknown";
}

function extractCodeFingerprint(result: NormalizableSarifResult): string | null {
  const candidates = [
    ...Object.values(result.partialFingerprints ?? {}),
    ...Object.values(result.fingerprints ?? {}),
  ];
  for (const val of candidates) {
    const trimmed = typeof val === "string" ? val.trim() : "";
    if (trimmed && trimmed.toLowerCase() !== "requires login") {
      return trimmed;
    }
  }
  return null;
}

function buildEvidence(
  result: NormalizableSarifResult,
  rule: NormalizableSarifRule | undefined,
  driverName: string,
  title: string,
  normalizedTitle: string
): FindingEvidence {
  const message =
    result.message?.text ??
    result.message?.markdown ??
    rule?.fullDescription?.text ??
    title;
  const snippet = result.locations?.[0]?.physicalLocation?.region?.snippet?.text;
  const rawTags = rule?.properties?.["tags"];
  const tags = Array.isArray(rawTags)
    ? rawTags.filter((t): t is string => typeof t === "string")
    : undefined;

  const mergedFingerprints: Record<string, string> = {};
  for (const [k, v] of Object.entries({
    ...result.fingerprints,
    ...result.partialFingerprints,
  })) {
    if (typeof v === "string" && v.trim()) {
      mergedFingerprints[k] = v;
    }
  }

  const hasProps =
    result.properties && Object.keys(result.properties).length > 0;

  return {
    message,
    ...(snippet ? { snippet } : {}),
    driverName,
    normalizedTitle,
    ...(rule?.helpUri ? { helpUri: rule.helpUri } : {}),
    ...(tags && tags.length > 0 ? { tags } : {}),
    ...(hasProps ? { properties: result.properties } : {}),
    ...(Object.keys(mergedFingerprints).length > 0
      ? { fingerprints: mergedFingerprints }
      : {}),
  };
}

/**
 * Normalize a parsed SARIF 2.1.0 document (such as result.sarif) into records
 * matching the Sprint 2 PostgreSQL security.issues and security.issue_occurrences schema.
 */
export function normalizeSarif(
  sarif: NormalizableSarifLog,
  options: NormalizeSarifOptions = {}
): NormalizedFinding[] {
  if (!sarif || !Array.isArray(sarif.runs)) {
    throw new Error(
      "Invalid SARIF payload: expected an object with a runs array."
    );
  }

  const defaultRepoId = resolveLogRepoId(sarif, options);
  const repoRoots = collectBaseRoots(sarif, options.repoRoot);
  const findings: NormalizedFinding[] = [];

  for (const run of sarif.runs) {
    const driverName =
      run.tool?.driver?.name || run.tool?.driver?.fullName || "unknown";
    const scanner = normalizeScanner(driverName);
    const repoId = options.repoId ?? resolveRunRepoId(run) ?? defaultRepoId;
    const ruleLookup = createRuleLookup(run);

    for (const result of run.results ?? []) {
      const rule = findMatchingRule(ruleLookup, result);
      const ruleId = result.ruleId ?? result.rule?.id ?? rule?.id ?? null;
      const title =
        rule?.shortDescription?.text ||
        rule?.name ||
        ruleId ||
        result.message?.text ||
        "Untitled Finding";
      const normalizedTitle = normalizeTitle(title);

      const physLoc = result.locations?.[0]?.physicalLocation;
      const region = physLoc?.region;

      findings.push({
        repoId,
        scanner,
        ruleId,
        title,
        normalizedTitle,
        severity: resolveSeverity(result, rule, scanner),
        filePath: toRepoRelativePath(
          physLoc?.artifactLocation?.uri,
          repoRoots,
          repoId
        ),
        startLine: toPositiveIntOrNull(region?.startLine),
        endLine: toPositiveIntOrNull(region?.endLine),
        startColumn: toPositiveIntOrNull(region?.startColumn),
        endColumn: toPositiveIntOrNull(region?.endColumn),
        codeFingerprint: extractCodeFingerprint(result),
        evidence: buildEvidence(
          result,
          rule,
          driverName,
          title,
          normalizedTitle
        ),
      });
    }
  }

  return findings;
}

/** Parse a raw SARIF JSON string and normalize all findings. */
export function normalizeSarifJson(
  rawJson: string,
  options?: NormalizeSarifOptions
): NormalizedFinding[] {
  const parsed = JSON.parse(rawJson) as NormalizableSarifLog;
  return normalizeSarif(parsed, options);
}

/** Synchronously read a .sarif file (defaults to ./packages/core/results/result.sarif) and normalize its findings. */
export function normalizeSarifFileSync(
  filePath: string = DEFAULT_RESULT_SARIF_PATH,
  options?: NormalizeSarifOptions
): NormalizedFinding[] {
  const raw = readFileSync(filePath, "utf8");
  return normalizeSarifJson(raw, options);
}

/** Asynchronously read a .sarif file (defaults to ./packages/core/results/result.sarif) and normalize its findings. */
export async function normalizeSarifFile(
  filePath: string = DEFAULT_RESULT_SARIF_PATH,
  options?: NormalizeSarifOptions
): Promise<NormalizedFinding[]> {
  const raw = await readFile(filePath, "utf8");
  return normalizeSarifJson(raw, options);
}

/** Synchronously write normalized findings JSON to disk, creating parent directories if needed. */
export function writeNormalizedFindingsSync(
  outputPath: string = DEFAULT_NORMALIZED_OUTPUT_PATH,
  findings: NormalizedFinding[]
): string {
  const resolved = resolve(outputPath);
  mkdirSync(dirname(resolved), { recursive: true });
  writeFileSync(resolved, `${JSON.stringify(findings, null, 2)}\n`, "utf8");
  return outputPath;
}

/** Asynchronously write normalized findings JSON to disk, creating parent directories if needed. */
export async function writeNormalizedFindings(
  outputPath: string = DEFAULT_NORMALIZED_OUTPUT_PATH,
  findings: NormalizedFinding[]
): Promise<string> {
  const resolved = resolve(outputPath);
  await mkdir(dirname(resolved), { recursive: true });
  await writeFile(resolved, `${JSON.stringify(findings, null, 2)}\n`, "utf8");
  return outputPath;
}

/** Synchronously read result.sarif, normalize its findings, and write normalized-findings.json. */
export function normalizeAndSaveSarifSync(
  inputPath: string = DEFAULT_RESULT_SARIF_PATH,
  outputPath: string = DEFAULT_NORMALIZED_OUTPUT_PATH,
  options?: NormalizeSarifOptions
): { inputPath: string; outputPath: string; findings: NormalizedFinding[] } {
  const findings = normalizeSarifFileSync(inputPath, options);
  writeNormalizedFindingsSync(outputPath, findings);
  return { inputPath, outputPath, findings };
}

/** Asynchronously read result.sarif, normalize its findings, and write normalized-findings.json. */
export async function normalizeAndSaveSarif(
  inputPath: string = DEFAULT_RESULT_SARIF_PATH,
  outputPath: string = DEFAULT_NORMALIZED_OUTPUT_PATH,
  options?: NormalizeSarifOptions
): Promise<{ inputPath: string; outputPath: string; findings: NormalizedFinding[] }> {
  const findings = await normalizeSarifFile(inputPath, options);
  await writeNormalizedFindings(outputPath, findings);
  return { inputPath, outputPath, findings };
}
