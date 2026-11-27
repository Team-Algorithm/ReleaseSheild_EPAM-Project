import { describe, it, expect, vi, afterEach } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  deduplicateFindings,
  deduplicateWithStats,
  writeDeduplicatedFindings,
  writeDeduplicatedFindingsSync,
  type FingerprintedFinding,
} from "../../packages/core/src/Deduplication/deduplicate.js";
import { generateIssueFingerprint } from "../../packages/core/src/Fingerprinting/fingerprint.js";
import type { NormalizedFinding } from "../../packages/core/src/Normalization/normalize.js";
import { runScan } from "../../packages/core/src/scan.js";
import * as toolsModule from "../../packages/core/src/Scanner/tools.js";
import type { ToolRunner, ToolRunOptions, ToolRunOutput } from "../../packages/core/src/types.js";

function makeFinding(
  overrides: Partial<FingerprintedFinding> = {}
): FingerprintedFinding {
  return {
    repoId: "repo-alpha",
    scanner: "semgrep",
    ruleId: "js.security.sql-injection",
    title: "SQL Injection",
    normalizedTitle: "sql-injection",
    severity: "high",
    filePath: "src/db.ts",
    startLine: 12,
    endLine: 12,
    startColumn: 5,
    endColumn: 42,
    codeFingerprint: "code-fp-1",
    issueFingerprint: "issue-fp-1",
    evidence: {
      message: "Potential SQL injection",
      snippet: "db.query(userInput)",
      driverName: "Semgrep OSS",
    },
    ...overrides,
  };
}

describe("Repository-scoped Deduplication (Phase 3)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("handles empty input cleanly with zero counts", () => {
    const result = deduplicateWithStats([]);
    expect(result).toEqual({
      uniqueFindings: [],
      duplicateFindings: [],
      issues: [],
      totalInput: 0,
      duplicatesRemoved: 0,
    });
    expect(deduplicateFindings([])).toEqual([]);
  });

  it("handles a single finding without duplicates", () => {
    const finding = makeFinding();
    const result = deduplicateWithStats([finding]);

    expect(result.totalInput).toBe(1);
    expect(result.duplicatesRemoved).toBe(0);
    expect(result.uniqueFindings).toHaveLength(1);
    expect(result.duplicateFindings).toHaveLength(0);
    expect(result.issues).toHaveLength(1);
    expect(result.issues[0]).toMatchObject({
      repoId: "repo-alpha",
      fingerprint: "issue-fp-1",
      title: "SQL Injection",
      severity: "high",
    });
    expect(result.issues[0].occurrences).toHaveLength(1);
    expect(deduplicateFindings([finding])).toEqual(result.uniqueFindings);
  });

  it("groups repeated identical findings and tracks occurrences accurately", () => {
    const f1 = makeFinding({ startLine: 10, endLine: 10 });
    const f2 = makeFinding({ startLine: 25, endLine: 25, scanner: "trivy" });
    const f3 = makeFinding({ startLine: 40, endLine: 40 });

    const result = deduplicateWithStats([f1, f2, f3]);

    expect(result.totalInput).toBe(3);
    expect(result.duplicatesRemoved).toBe(2);
    expect(result.uniqueFindings).toHaveLength(1);
    expect(result.uniqueFindings[0].startLine).toBe(10);
    expect(result.duplicateFindings).toHaveLength(2);
    expect(result.issues).toHaveLength(1);
    expect(result.issues[0].occurrences).toHaveLength(3);
    expect(result.issues[0].occurrences[0].startLine).toBe(10);
    expect(result.issues[0].occurrences[1].scanner).toBe("trivy");
    expect(result.issues[0].occurrences[2].startLine).toBe(40);
  });

  it("keeps identical fingerprints in different repositories as separate issues", () => {
    const fRepoA = makeFinding({ repoId: "repo-a", issueFingerprint: "fp-same" });
    const fRepoB = makeFinding({ repoId: "repo-b", issueFingerprint: "fp-same" });

    const result = deduplicateWithStats([fRepoA, fRepoB]);

    expect(result.totalInput).toBe(2);
    expect(result.duplicatesRemoved).toBe(0);
    expect(result.uniqueFindings).toHaveLength(2);
    expect(result.issues).toHaveLength(2);
    expect(result.issues.map((i) => i.repoId)).toEqual(["repo-a", "repo-b"]);
  });

  it("prevents composite key delimiter collisions across repositories", () => {
    const f1 = makeFinding({ repoId: "org::proj", issueFingerprint: "123" });
    const f2 = makeFinding({ repoId: "org", issueFingerprint: "proj::123" });

    const result = deduplicateWithStats([f1, f2]);

    expect(result.issues).toHaveLength(2);
    expect(result.uniqueFindings).toHaveLength(2);
    expect(result.duplicatesRemoved).toBe(0);
  });

  it("keeps different fingerprints in the same repository separate", () => {
    const f1 = makeFinding({ repoId: "repo-a", issueFingerprint: "fp-1" });
    const f2 = makeFinding({ repoId: "repo-a", issueFingerprint: "fp-2" });

    const result = deduplicateWithStats([f1, f2]);

    expect(result.totalInput).toBe(2);
    expect(result.duplicatesRemoved).toBe(0);
    expect(result.uniqueFindings).toHaveLength(2);
    expect(result.issues).toHaveLength(2);
  });

  it("does not merge different findings in the same file or with similar titles", () => {
    const f1 = makeFinding({
      filePath: "src/app.ts",
      title: "Hardcoded secret",
      issueFingerprint: "fp-secret-1",
    });
    const f2 = makeFinding({
      filePath: "src/app.ts",
      title: "Hardcoded secret",
      issueFingerprint: "fp-secret-2",
    });

    const result = deduplicateWithStats([f1, f2]);

    expect(result.uniqueFindings).toHaveLength(2);
    expect(result.issues).toHaveLength(2);
    expect(result.duplicatesRemoved).toBe(0);
  });

  it("generates fallback fingerprint when issueFingerprint is missing or blank, even without evidence", () => {
    const withoutFp = makeFinding({
      issueFingerprint: "   ",
      evidence: undefined,
      normalizedTitle: "",
    });
    const secondWithoutFp = makeFinding({
      issueFingerprint: "",
      evidence: undefined,
      normalizedTitle: "",
    });

    const expectedFp = generateIssueFingerprint({
      ...(withoutFp as unknown as NormalizedFinding),
      normalizedTitle: "sql-injection",
      evidence: { message: "SQL Injection" },
    });

    const result = deduplicateWithStats([withoutFp, secondWithoutFp]);

    expect(result.totalInput).toBe(2);
    expect(result.uniqueFindings).toHaveLength(1);
    expect(result.duplicateFindings).toHaveLength(1);
    expect(result.duplicatesRemoved).toBe(1);
    expect(result.issues[0].fingerprint).toBe(expectedFp);
    expect(result.uniqueFindings[0].issueFingerprint).toBe(expectedFp);
  });

  it("retains the highest severity among occurrences of the same issue", () => {
    const low = makeFinding({ severity: "low" });
    const critical = makeFinding({ severity: "critical" });
    const medium = makeFinding({ severity: "medium" });
    const upperHigh = makeFinding({
      severity: "HIGH" as FingerprintedFinding["severity"],
    });

    const result = deduplicateWithStats([low, upperHigh, critical, medium]);

    expect(result.issues).toHaveLength(1);
    expect(result.issues[0].severity).toBe("critical");
    expect(result.issues[0].occurrences.map((o) => o.severity)).toEqual([
      "low",
      "high",
      "critical",
      "medium",
    ]);
  });

  it("preserves scanner, rule, location, severity, codeFingerprint, and evidence per occurrence", () => {
    const f1 = makeFinding({
      scanner: "semgrep",
      ruleId: "rule-a",
      filePath: "src/a.ts",
      startLine: 5,
      endLine: 7,
      startColumn: 2,
      endColumn: 18,
      severity: "medium",
      codeFingerprint: "code-1",
      evidence: { message: "msg 1", snippet: "code 1" },
    });
    const f2 = makeFinding({
      scanner: "trivy",
      ruleId: "CVE-2024-0001",
      filePath: "package-lock.json",
      startLine: null,
      endLine: null,
      startColumn: null,
      endColumn: null,
      severity: "high",
      codeFingerprint: "code-2",
      evidence: undefined,
    });

    const result = deduplicateWithStats([f1, f2]);
    expect(result.issues).toHaveLength(1);

    const [occ1, occ2] = result.issues[0].occurrences;
    expect(occ1).toEqual({
      scanner: "semgrep",
      ruleId: "rule-a",
      filePath: "src/a.ts",
      startLine: 5,
      endLine: 7,
      startColumn: 2,
      endColumn: 18,
      severity: "medium",
      codeFingerprint: "code-1",
      evidence: { message: "msg 1", snippet: "code 1" },
    });
    expect(occ2).toEqual({
      scanner: "trivy",
      ruleId: "CVE-2024-0001",
      filePath: "package-lock.json",
      startLine: null,
      endLine: null,
      startColumn: null,
      endColumn: null,
      severity: "high",
      codeFingerprint: "code-2",
      evidence: null,
    });
  });

  it("produces stable, deterministic output across repeated runs", () => {
    const input = [
      makeFinding({ repoId: "r1", issueFingerprint: "fp-a", severity: "low" }),
      makeFinding({ repoId: "r2", issueFingerprint: "fp-a", severity: "high" }),
      makeFinding({ repoId: "r1", issueFingerprint: "fp-a", severity: "critical" }),
      makeFinding({ repoId: "r1", issueFingerprint: "fp-b", severity: "medium" }),
    ];

    const run1 = deduplicateWithStats(input);
    const run2 = deduplicateWithStats(input);

    expect(run1).toEqual(run2);
  });

  it("does not mutate input findings or nested evidence", () => {
    const evidence = Object.freeze({
      message: "Secret detected",
      tags: Object.freeze(["secret"]) as string[],
    });
    const finding = Object.freeze(
      makeFinding({
        issueFingerprint: "",
        evidence,
      })
    );
    const input = Object.freeze([finding]);

    const result = deduplicateWithStats(input);

    expect(finding.issueFingerprint).toBe("");
    expect(result.uniqueFindings[0]).not.toBe(finding);
    expect(result.uniqueFindings[0].issueFingerprint).toMatch(/^[a-f0-9]{64}$/);
  });

  it("throws TypeError on invalid non-array or non-object inputs", () => {
    expect(() =>
      deduplicateWithStats(null as unknown as FingerprintedFinding[])
    ).toThrow(TypeError);
    expect(() =>
      deduplicateWithStats([null as unknown as FingerprintedFinding])
    ).toThrow(TypeError);
  });

  it("writes valid JSON and creates parent directories via writeDeduplicatedFindings", async () => {
    const baseDir = mkdtempSync(path.join(tmpdir(), "rs-dedup-test-"));
    const asyncOutPath = path.join(baseDir, "nested", "dir", "deduplicated-findings.json");
    const syncOutPath = path.join(baseDir, "nested-sync", "deduplicated-sync.json");

    try {
      const result = deduplicateWithStats([
        makeFinding({ severity: "low" }),
        makeFinding({ severity: "high" }),
      ]);

      const returnedAsync = await writeDeduplicatedFindings(asyncOutPath, result);
      const returnedSync = writeDeduplicatedFindingsSync(syncOutPath, result);

      expect(returnedAsync).toBe(asyncOutPath);
      expect(returnedSync).toBe(syncOutPath);
      expect(existsSync(asyncOutPath)).toBe(true);
      expect(existsSync(syncOutPath)).toBe(true);

      const parsedAsync = JSON.parse(readFileSync(asyncOutPath, "utf8"));
      const parsedSync = JSON.parse(readFileSync(syncOutPath, "utf8"));
      expect(parsedAsync).toEqual(result);
      expect(parsedSync).toEqual(result);
    } finally {
      rmSync(baseDir, { recursive: true, force: true });
    }
  });

  it("integrates normalization, fingerprinting, and deduplication in runScan()", async () => {
    const baseDir = mkdtempSync(path.join(tmpdir(), "rs-scan-dedup-"));
    const customSarifOut = path.join(baseDir, "result.sarif");

    const sampleSarif = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "gitleaks",
              rules: [{ id: "generic-api-key", name: "GenericApiKey" }],
            },
          },
          results: [
            {
              ruleId: "generic-api-key",
              level: "error",
              message: { text: "Secret found" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: ".env" },
                    region: { startLine: 1 },
                  },
                },
              ],
            },
            {
              ruleId: "generic-api-key",
              level: "warning",
              message: { text: "Secret found" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: ".env" },
                    region: { startLine: 5 },
                  },
                },
              ],
            },
          ],
        },
      ],
    };

    try {
      vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
        name: toolName,
        isAvailable: async () => true,
        buildArgs: () => [],
        run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
          await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
          await fs.writeFile(options.outputPath, JSON.stringify(sampleSarif), "utf-8");
          return {
            tool: toolName,
            status: "done",
            durationSec: 0.1,
            counts: { high: 1, medium: 1, low: 0 },
          };
        },
      } as unknown as ToolRunner));

      const summary = await runScan(["gitleaks"], undefined, {
        targetPath: baseDir,
        outputPath: customSarifOut,
        sarifFiles: {
          gitleaks: path.join(baseDir, "gitleaks.sarif"),
          trivy: path.join(baseDir, "trivy.sarif"),
          semgrep: path.join(baseDir, "semgrep.sarif"),
        },
      });

      expect(summary.savedPath).toBe(customSarifOut);

      const dedupPath = path.join(baseDir, "deduplicated-findings.json");
      expect(existsSync(path.join(baseDir, "normalized-findings.json"))).toBe(true);
      expect(existsSync(path.join(baseDir, "fingerprinted-findings.json"))).toBe(true);
      expect(existsSync(dedupPath)).toBe(true);

      const dedupResult = JSON.parse(readFileSync(dedupPath, "utf8"));
      expect(dedupResult.totalInput).toBe(2);
      expect(dedupResult.duplicatesRemoved).toBe(1);
      expect(dedupResult.uniqueFindings).toHaveLength(1);
      expect(dedupResult.issues).toHaveLength(1);
      expect(dedupResult.issues[0].severity).toBe("high");
      expect(dedupResult.issues[0].occurrences).toHaveLength(2);
    } finally {
      rmSync(baseDir, { recursive: true, force: true });
    }
  });
});
