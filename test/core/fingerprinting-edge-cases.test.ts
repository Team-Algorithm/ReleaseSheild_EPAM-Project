import { describe, it, expect } from "vitest";
import { normalizeSarifFileSync } from "../../packages/core/src/Normalization/normalize.js";
import { generateIssueFingerprint } from "../../packages/core/src/Fingerprinting/fingerprint.js";

const findings = normalizeSarifFileSync(
  "test/core/fixtures/trivy-sample.sarif"
);

const baseFinding = {
  ...findings[0],
  scanner: "semgrep" as const,
  ruleId: "test-rule",
  normalizedTitle: "potentially unsafe operation",
};

describe("Fingerprinting edge cases", () => {
  it("distinguishes findings with the same rule in different files", () => {
    const first = {
      ...baseFinding,
      filePath: "src/first.py",
    };

    const second = {
      ...baseFinding,
      filePath: "src/second.py",
    };

    expect(generateIssueFingerprint(first))
      .not.toBe(generateIssueFingerprint(second));
  });

  it("distinguishes findings with different normalized titles", () => {
    const first = {
      ...baseFinding,
      normalizedTitle: "unsafe input handling",
    };

    const second = {
      ...baseFinding,
      normalizedTitle: "hardcoded credential",
    };

    expect(generateIssueFingerprint(first))
      .not.toBe(generateIssueFingerprint(second));
  });

  it("does not use line numbers as primary issue identity", () => {
    const first = {
      ...baseFinding,
      startLine: 10,
      endLine: 10,
    };

    const second = {
      ...baseFinding,
      startLine: 25,
      endLine: 25,
    };

    expect(generateIssueFingerprint(first))
      .toBe(generateIssueFingerprint(second));
  });
});
