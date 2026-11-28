import { mkdirSync, writeFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  normalizeTitle,
  type FindingEvidence,
  type NormalizedFinding,
  type NormalizedScanner,
  type NormalizedSeverity,
} from "../Normalization/normalize.js";
import { generateIssueFingerprint } from "../Fingerprinting/fingerprint.js";

export const DEFAULT_DEDUPLICATED_OUTPUT_PATH =
  "./packages/core/results/deduplicated-findings.json";

export interface FingerprintedFinding
  extends Omit<NormalizedFinding, "evidence"> {
  codeFingerprint: string | null;
  issueFingerprint: string;
  evidence?: FindingEvidence;
}

export interface IssueOccurrenceInput {
  scanner: NormalizedScanner;
  ruleId: string | null;
  filePath: string;
  startLine: number | null;
  endLine: number | null;
  startColumn: number | null;
  endColumn: number | null;
  severity: NormalizedSeverity;
  codeFingerprint: string | null;
  evidence: FindingEvidence | null;
}

export interface DeduplicatedIssue {
  repoId: string;
  fingerprint: string; // maps to security.issues.fingerprint
  title: string;
  severity: NormalizedSeverity;
  occurrences: IssueOccurrenceInput[];
}

export interface DeduplicationResult {
  uniqueFindings: FingerprintedFinding[];
  duplicateFindings: FingerprintedFinding[];
  issues: DeduplicatedIssue[];
  totalInput: number;
  duplicatesRemoved: number;
}

const SEVERITY_RANK: Record<NormalizedSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
};

/**
 * Normalizes a severity value to a valid lowercase NormalizedSeverity.
 * Falls back to "unknown" for unrecognized or missing values.
 */
export function normalizeSeverity(
  severity: string | null | undefined
): NormalizedSeverity {
  if (typeof severity !== "string") {
    return "unknown";
  }
  const lower = severity.trim().toLowerCase() as NormalizedSeverity;
  return Object.prototype.hasOwnProperty.call(SEVERITY_RANK, lower)
    ? lower
    : "unknown";
}

function higherSeverity(
  a: NormalizedSeverity,
  b: NormalizedSeverity
): NormalizedSeverity {
  const normA = normalizeSeverity(a);
  const normB = normalizeSeverity(b);
  return SEVERITY_RANK[normB] > SEVERITY_RANK[normA] ? normB : normA;
}

/**
 * Builds an unambiguous, collision-safe repository-scoped composite key.
 * JSON tuple encoding prevents delimiter collisions even when repoId contains "::" or special characters.
 */
export function buildRepoScopedKey(repoId: string, fingerprint: string): string {
  return JSON.stringify([repoId, fingerprint]);
}

function resolveRepoId(repoId: string | null | undefined): string {
  if (typeof repoId !== "string") {
    return "unknown-repo";
  }
  const trimmed = repoId.trim();
  return trimmed.length > 0 ? trimmed : "unknown-repo";
}

function cloneEvidence(
  evidence: FindingEvidence | undefined
): FindingEvidence | undefined {
  if (!evidence) {
    return undefined;
  }
  return {
    ...evidence,
    ...(evidence.tags ? { tags: [...evidence.tags] } : {}),
    ...(evidence.properties ? { properties: { ...evidence.properties } } : {}),
    ...(evidence.fingerprints
      ? { fingerprints: { ...evidence.fingerprints } }
      : {}),
  };
}

function resolveIssueFingerprint(raw: FingerprintedFinding): string {
  if (
    typeof raw.issueFingerprint === "string" &&
    raw.issueFingerprint.trim().length > 0
  ) {
    return raw.issueFingerprint.trim();
  }

  const title =
    typeof raw.title === "string" && raw.title.trim().length > 0
      ? raw.title
      : "Untitled Finding";
  const normalizedTitle =
    typeof raw.normalizedTitle === "string" &&
    raw.normalizedTitle.trim().length > 0
      ? raw.normalizedTitle
      : normalizeTitle(title);

  const safeFinding: NormalizedFinding = {
    repoId: resolveRepoId(raw.repoId),
    scanner: raw.scanner,
    ruleId: raw.ruleId ?? null,
    title,
    normalizedTitle,
    severity: normalizeSeverity(raw.severity),
    filePath:
      typeof raw.filePath === "string" && raw.filePath.trim().length > 0
        ? raw.filePath
        : "unknown",
    startLine: raw.startLine ?? null,
    endLine: raw.endLine ?? null,
    startColumn: raw.startColumn ?? null,
    endColumn: raw.endColumn ?? null,
    codeFingerprint: raw.codeFingerprint ?? null,
    evidence: {
      ...(raw.evidence ?? {}),
      message: raw.evidence?.message ?? title,
    },
  };

  return generateIssueFingerprint(safeFinding);
}

function toOccurrence(f: FingerprintedFinding): IssueOccurrenceInput {
  return {
    scanner: f.scanner,
    ruleId: f.ruleId ?? null,
    filePath: f.filePath,
    startLine: f.startLine ?? null,
    endLine: f.endLine ?? null,
    startColumn: f.startColumn ?? null,
    endColumn: f.endColumn ?? null,
    severity: normalizeSeverity(f.severity),
    codeFingerprint: f.codeFingerprint ?? null,
    evidence: cloneEvidence(f.evidence) ?? null,
  };
}

/**
 * Layer 1 (In-Memory): Repository-scoped deduplication & segregation.
 * Composite key: JSON tuple `[repoId, issueFingerprint]`.
 */
export function deduplicateWithStats(
  findings: readonly FingerprintedFinding[]
): DeduplicationResult {
  if (!Array.isArray(findings)) {
    throw new TypeError("Invalid findings input: expected an array.");
  }

  const issueMap = new Map<string, DeduplicatedIssue>();
  const uniqueFindings: FingerprintedFinding[] = [];
  const duplicateFindings: FingerprintedFinding[] = [];

  for (const raw of findings) {
    if (!raw || typeof raw !== "object") {
      throw new TypeError(
        "Invalid finding entry: expected each finding to be an object."
      );
    }

    const repoId = resolveRepoId(raw.repoId);
    const fp = resolveIssueFingerprint(raw);
    const severity = normalizeSeverity(raw.severity);

    const finding: FingerprintedFinding = {
      ...raw,
      repoId,
      severity,
      issueFingerprint: fp,
      ...(raw.evidence !== undefined
        ? { evidence: cloneEvidence(raw.evidence) }
        : {}),
    };

    const repoAwareKey = buildRepoScopedKey(repoId, fp);
    const existingIssue = issueMap.get(repoAwareKey);

    if (!existingIssue) {
      issueMap.set(repoAwareKey, {
        repoId,
        fingerprint: fp,
        title: finding.title,
        severity,
        occurrences: [toOccurrence(finding)],
      });
      uniqueFindings.push(finding);
    } else {
      existingIssue.severity = higherSeverity(existingIssue.severity, severity);
      existingIssue.occurrences.push(toOccurrence(finding));
      duplicateFindings.push(finding);
    }
  }

  return {
    uniqueFindings,
    duplicateFindings,
    issues: Array.from(issueMap.values()),
    totalInput: findings.length,
    duplicatesRemoved: duplicateFindings.length,
  };
}

export function deduplicateFindings(
  findings: readonly FingerprintedFinding[]
): FingerprintedFinding[] {
  return deduplicateWithStats(findings).uniqueFindings;
}

export async function writeDeduplicatedFindings(
  outputPath: string = DEFAULT_DEDUPLICATED_OUTPUT_PATH,
  result: DeduplicationResult | readonly FingerprintedFinding[]
): Promise<string> {
  const resolved = path.resolve(outputPath);
  await mkdir(path.dirname(resolved), { recursive: true });
  const uniqueFindings: readonly FingerprintedFinding[] = Array.isArray(result)
    ? result
    : (result as DeduplicationResult).uniqueFindings;
  await writeFile(
    resolved,
    `${JSON.stringify(uniqueFindings, null, 2)}\n`,
    "utf8"
  );
  return outputPath;
}

export function writeDeduplicatedFindingsSync(
  outputPath: string = DEFAULT_DEDUPLICATED_OUTPUT_PATH,
  result: DeduplicationResult | readonly FingerprintedFinding[]
): string {
  const resolved = path.resolve(outputPath);
  mkdirSync(path.dirname(resolved), { recursive: true });
  const uniqueFindings: readonly FingerprintedFinding[] = Array.isArray(result)
    ? result
    : (result as DeduplicationResult).uniqueFindings;
  writeFileSync(
    resolved,
    `${JSON.stringify(uniqueFindings, null, 2)}\n`,
    "utf8"
  );
  return outputPath;
}
