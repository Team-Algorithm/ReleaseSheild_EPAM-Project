
import { describe, it, expect } from "vitest";
import {
  normalizeSarifFileSync,
} from "../../packages/core/src/Normalization/normalize.js";
import {
  generateCodeFingerprint,
  generateIssueFingerprint,
  fingerprintFinding,
} from "../../packages/core/src/Fingerprinting/fingerprint.js";

const trivyFindings = normalizeSarifFileSync(
  "test/core/fixtures/trivy-sample.sarif"
);

const gitleaksFindings = normalizeSarifFileSync(
  "test/core/fixtures/gitleaks-sample.sarif"
);

describe("Fingerprinting with real SARIF fixtures", () => {
  it("generates valid SHA-256 fingerprints for Trivy findings", () => {
    expect(trivyFindings.length).toBeGreaterThan(0);

    for (const finding of trivyFindings) {
      expect(generateCodeFingerprint(finding)).toMatch(/^[a-f0-9]{64}$/);
      expect(generateIssueFingerprint(finding)).toMatch(/^[a-f0-9]{64}$/);
    }
  });

  it("generates issue fingerprints without code fingerprints for Gitleaks findings", () => {
    expect(gitleaksFindings.length).toBeGreaterThan(0);

    for (const finding of gitleaksFindings) {
      expect(generateCodeFingerprint(finding)).toBeUndefined();
      expect(generateIssueFingerprint(finding)).toMatch(/^[a-f0-9]{64}$/);
    }
  });

  it("uses the same code fingerprint but different issue fingerprints for Trivy CVEs in the same package", () => {
    const results = trivyFindings.map(fingerprintFinding);

    expect(new Set(results.map((item) => item.codeFingerprint)).size).toBe(1);
    expect(new Set(results.map((item) => item.issueFingerprint)).size)
      .toBe(results.length);
  });

  it("generates consistent fingerprints for repeated findings", () => {
    for (const finding of [...trivyFindings, ...gitleaksFindings]) {
      expect(generateCodeFingerprint(finding)).toBe(
        generateCodeFingerprint(finding)
      );
      expect(generateIssueFingerprint(finding)).toBe(
        generateIssueFingerprint(finding)
      );
    }
  });

  it("does not use Gitleaks evidence or secret snippets in fingerprints", () => {
    for (const finding of gitleaksFindings) {
      const originalCodeFingerprint = generateCodeFingerprint(finding);
      const originalIssueFingerprint = generateIssueFingerprint(finding);

      const modifiedFinding = {
        ...finding,
        evidence: {
          ...finding.evidence,
          snippet: "CHANGED_SECRET_VALUE",
          message: "CHANGED_MESSAGE",
        },
      };

      expect(generateCodeFingerprint(modifiedFinding)).toBe(
        originalCodeFingerprint
      );
      expect(generateIssueFingerprint(modifiedFinding)).toBe(
        originalIssueFingerprint
      );
    }
  });

  it("returns fingerprinted copies without modifying normalized findings", () => {
    for (const finding of [...trivyFindings, ...gitleaksFindings]) {
      const originalCodeFingerprint = finding.codeFingerprint;
      const result = fingerprintFinding(finding);

      expect(result).not.toBe(finding);
      expect(result.issueFingerprint).toMatch(/^[a-f0-9]{64}$/);
      expect(finding.codeFingerprint).toBe(originalCodeFingerprint);
    }
  });
});
