import { createHash } from "node:crypto";
import type { NormalizedFinding } from "../Normalization/normalize.js";

function normalizeFingerprintValue(value: string): string {
  return value
    .trim()
    .replace(/\\/g, "/")
    .replace(/\/+/g, "/")
    .toLowerCase();
}

function createFingerprint(input: unknown[]): string {
  return createHash("sha256")
    .update(JSON.stringify(input), "utf8")
    .digest("hex");
}

function extractPackageName(
  finding: NormalizedFinding
): string | undefined {
  if (finding.scanner !== "trivy") {
    return undefined;
  }

  const match = finding.evidence.message.match(
    /^Package:\s*([^\r\n]+)/im
  );

  return match?.[1]
    ? normalizeFingerprintValue(match[1])
    : undefined;
}

export function generateCodeFingerprint(
  finding: NormalizedFinding
): string | undefined {
  const filePath = normalizeFingerprintValue(finding.filePath);

  if (!filePath || filePath === "unknown") {
    return undefined;
  }

  // Trivy package-based identity.
  const packageName = extractPackageName(finding);

  if (packageName) {
    return createFingerprint([
      "rs-code-v1",
      "package",
      filePath,
      packageName,
    ]);
  }

  // No verified safe code identity for Gitleaks or Semgrep yet.
  return undefined;
}

export function generateIssueFingerprint(
  finding: NormalizedFinding
): string {
  const codeFingerprint = generateCodeFingerprint(finding);
  const ruleId = finding.ruleId?.trim();

  const canonicalRuleId =
    ruleId && ruleId.toLowerCase() !== "unknown-rule"
      ? ruleId.toUpperCase()
      : "unknown-rule";

  // Gitleaks: never use secret, snippet, commit metadata or line numbers.
  if (finding.scanner === "gitleaks") {
    return createFingerprint([
      "rs-issue-v1",
      finding.scanner,
      canonicalRuleId,
      normalizeFingerprintValue(finding.filePath),
      normalizeFingerprintValue(finding.normalizedTitle),
    ]);
  }

  // Semgrep: use safe normalized metadata when code identity is unavailable.
  if (finding.scanner === "semgrep") {
    return createFingerprint([
      "rs-issue-v1",
      finding.scanner,
      canonicalRuleId,
      normalizeFingerprintValue(finding.filePath),
      normalizeFingerprintValue(finding.normalizedTitle),
    ]);
  }

  return createFingerprint([
    "rs-issue-v1",
    finding.scanner,
    canonicalRuleId,
    codeFingerprint ?? null,
    canonicalRuleId === "unknown-rule"
      ? normalizeFingerprintValue(finding.normalizedTitle)
      : null,
  ]);
}

export function fingerprintFinding(finding: NormalizedFinding) {
  const codeFingerprint = generateCodeFingerprint(finding);

  return {
    ...finding,
    codeFingerprint: codeFingerprint ?? null,
    issueFingerprint: generateIssueFingerprint(finding),
  };
}
