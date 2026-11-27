import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import type { NormalizedFinding } from "../../packages/core/src/Normalization/normalize.js";
import {
  generateCodeFingerprint,
  generateIssueFingerprint,
  fingerprintFinding,
} from "../../packages/core/src/Fingerprinting/fingerprint.js";

function loadFindings(path: string): NormalizedFinding[] {
  return JSON.parse(readFileSync(path, "utf8")) as NormalizedFinding[];
}

const trivyFindings = loadFindings(
  "packages/core/results/normalized-trivy.json"
);

const gitleaksFindings = loadFindings(
  "packages/core/results/normalized-gitleaks.json"
);

describe("Fingerprinting with actual normalized JSON data", () => {
  it("processes all normalized Trivy findings", () => {
    expect(trivyFindings).toHaveLength(5);

    for (const finding of trivyFindings) {
      expect(generateCodeFingerprint(finding)).toMatch(/^[a-f0-9]{64}$/);
      expect(generateIssueFingerprint(finding)).toMatch(/^[a-f0-9]{64}$/);
    }
  });

  it("processes all normalized Gitleaks findings safely", () => {
    expect(gitleaksFindings).toHaveLength(3);

    for (const finding of gitleaksFindings) {
      expect(generateCodeFingerprint(finding)).toBeUndefined();
      expect(generateIssueFingerprint(finding)).toMatch(/^[a-f0-9]{64}$/);
    }
  });

  it("generates distinct issue fingerprints for Trivy findings", () => {
    const results = trivyFindings.map(fingerprintFinding);

    expect(
      new Set(results.map((finding) => finding.issueFingerprint)).size
    ).toBe(5);
  });

  it("generates distinct issue fingerprints for current Gitleaks findings", () => {
    const results = gitleaksFindings.map(fingerprintFinding);

    expect(
      new Set(results.map((finding) => finding.issueFingerprint)).size
    ).toBe(3);
  });

  it("does not modify the original normalized findings", () => {
    for (const finding of [...trivyFindings, ...gitleaksFindings]) {
      const originalCodeFingerprint = finding.codeFingerprint;

      const result = fingerprintFinding(finding);

      expect(result).not.toBe(finding);
      expect(finding.codeFingerprint).toBe(originalCodeFingerprint);
      expect(result.issueFingerprint).toMatch(/^[a-f0-9]{64}$/);
    }
  });
});
