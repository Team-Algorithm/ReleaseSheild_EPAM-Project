import { describe, it, expect, vi, afterEach } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
import * as deduplicationModule from "../../packages/core/src/Deduplication/deduplicate.js";
import { generateIssueFingerprint } from "../../packages/core/src/Fingerprinting/fingerprint.js";
import type { NormalizedFinding } from "../../packages/core/src/Normalization/normalize.js";
import { runScan, resolveScanRepoId } from "../../packages/core/src/scan.js";
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
      expect(parsedAsync).toEqual(result.uniqueFindings);
      expect(parsedSync).toEqual(result.uniqueFindings);
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
      expect(summary.deduplication).toEqual({
        totalInput: 2,
        uniqueIssues: 1,
        duplicatesRemoved: 1,
      });

      const dedupPath = path.join(baseDir, "deduplicated-findings.json");
      expect(existsSync(path.join(baseDir, "normalized-findings.json"))).toBe(true);
      expect(existsSync(path.join(baseDir, "fingerprinted-findings.json"))).toBe(true);
      expect(existsSync(dedupPath)).toBe(true);

      const dedupResult = JSON.parse(readFileSync(dedupPath, "utf8"));
      expect(Array.isArray(dedupResult)).toBe(true);
      expect(dedupResult).toHaveLength(1);
      expect(dedupResult[0].repoId).toBe(path.basename(baseDir));
      expect(dedupResult[0].ruleId).toBe("generic-api-key");
      expect(dedupResult[0].severity).toBe("high");
    } finally {
      rmSync(baseDir, { recursive: true, force: true });
    }
  });

  it("deduplicates equivalent findings even when SARIF runs have differing originalUriBaseIds, while keeping distinct findings separate", async () => {
    const baseDir = mkdtempSync(path.join(tmpdir(), "rs-scan-repoid-"));
    const customSarifOut = path.join(baseDir, "result.sarif");

    const semgrepSarif = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Semgrep OSS",
              rules: [
                { id: "js.sql-injection", name: "SQL Injection" },
                { id: "js.xss-injection", name: "SQL Injection" },
              ],
            },
          },
          originalUriBaseIds: {
            ROOTPATH: { uri: "file:///C:/different/root/repo-a/" },
          },
          results: [
            {
              ruleId: "js.sql-injection",
              level: "error",
              message: { text: "SQL Injection" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "src/api.ts" },
                    region: { startLine: 10 },
                  },
                },
              ],
            },
            {
              // Same file and message/title, but different ruleId -> must remain separate
              ruleId: "js.xss-injection",
              level: "warning",
              message: { text: "SQL Injection" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "src/api.ts" },
                    region: { startLine: 15 },
                  },
                },
              ],
            },
          ],
        },
        {
          tool: {
            driver: {
              name: "Semgrep OSS",
              rules: [{ id: "js.sql-injection", name: "SQL Injection" }],
            },
          },
          originalUriBaseIds: {
            ROOTPATH: { uri: "file:///R:/another-name/" },
          },
          results: [
            {
              // Equivalent to first finding (same scanner, ruleId, file, title) in a run with different originalUriBaseIds
              ruleId: "js.sql-injection",
              level: "warning",
              message: { text: "SQL Injection" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "src/api.ts" },
                    region: { startLine: 25 },
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
          await fs.writeFile(options.outputPath, JSON.stringify(semgrepSarif), "utf-8");
          return {
            tool: toolName,
            status: "done",
            durationSec: 0.1,
            counts: { high: 1, medium: 2, low: 0 },
          };
        },
      } as unknown as ToolRunner));

      const summary = await runScan(["semgrep"], undefined, {
        targetPath: baseDir,
        outputPath: customSarifOut,
        sarifFiles: {
          semgrep: path.join(baseDir, "semgrep.sarif"),
          trivy: path.join(baseDir, "trivy.sarif"),
          gitleaks: path.join(baseDir, "gitleaks.sarif"),
        },
      });

      const dedupResult = JSON.parse(
        readFileSync(path.join(baseDir, "deduplicated-findings.json"), "utf8")
      );

      // Invariants: 3 raw inputs -> 2 unique issues (sql-injection x2 grouped, xss-injection x1 separate)
      expect(Array.isArray(dedupResult)).toBe(true);
      expect(dedupResult).toHaveLength(2);
      expect(summary.deduplication).toEqual({
        totalInput: 3,
        uniqueIssues: 2,
        duplicatesRemoved: 1,
      });
    } finally {
      rmSync(baseDir, { recursive: true, force: true });
    }
  });

  it("removes old or partial output files when a scan fails so stale results cannot be reused", async () => {
    const baseDir = mkdtempSync(path.join(tmpdir(), "rs-scan-stale-"));
    const customSarifOut = path.join(baseDir, "result.sarif");
    const normPath = path.join(baseDir, "normalized-findings.json");
    const fpPath = path.join(baseDir, "fingerprinted-findings.json");
    const dedupPath = path.join(baseDir, "deduplicated-findings.json");

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
            },
          ],
        },
      ],
    };

    try {
      // Seed stale files from a prior run
      await fs.writeFile(customSarifOut, "stale", "utf-8");
      await fs.writeFile(normPath, "stale", "utf-8");
      await fs.writeFile(fpPath, "stale", "utf-8");
      await fs.writeFile(dedupPath, "stale", "utf-8");

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
            counts: { high: 1, medium: 0, low: 0 },
          };
        },
      } as unknown as ToolRunner));

      // Simulate failure during deduplication write after SARIF/normalized/fingerprinted were written
      vi.spyOn(deduplicationModule, "writeDeduplicatedFindings").mockRejectedValueOnce(
        new Error("Disk full")
      );

      const summary = await runScan(["gitleaks"], undefined, {
        targetPath: baseDir,
        outputPath: customSarifOut,
        sarifFiles: {
          gitleaks: path.join(baseDir, "gitleaks.sarif"),
          trivy: path.join(baseDir, "trivy.sarif"),
          semgrep: path.join(baseDir, "semgrep.sarif"),
        },
      });

      expect(summary.savedPath).toBe("");
      expect(summary.deduplication).toBeUndefined();
      expect(summary.tools[0].status).toBe("failed");
      expect(existsSync(customSarifOut)).toBe(false);
      expect(existsSync(normPath)).toBe(false);
      expect(existsSync(fpPath)).toBe(false);
      expect(existsSync(dedupPath)).toBe(false);
    } finally {
      rmSync(baseDir, { recursive: true, force: true });
    }
  });

  it("completes best-effort cleanup without masking the scan error when cleanup encounters an error", async () => {
    const baseDir = mkdtempSync(path.join(tmpdir(), "rs-scan-besteffort-"));
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
            counts: { high: 1, medium: 0, low: 0 },
          };
        },
      } as unknown as ToolRunner));

      // Trigger failure during post-processing to verify error reporting and cleanup
      vi.spyOn(deduplicationModule, "writeDeduplicatedFindings").mockRejectedValueOnce(
        new Error("Deduplication disk write failed")
      );

      const summary = await runScan(["gitleaks"], undefined, {
        targetPath: baseDir,
        outputPath: customSarifOut,
        sarifFiles: {
          gitleaks: path.join(baseDir, "gitleaks.sarif"),
          trivy: path.join(baseDir, "trivy.sarif"),
          semgrep: path.join(baseDir, "semgrep.sarif"),
        },
      });

      // Scan reports failure and does not crash or mask the failure
      expect(summary.savedPath).toBe("");
      expect(summary.deduplication).toBeUndefined();
      expect(summary.tools[0].status).toBe("failed");
      expect(summary.tools[0].error).toContain("Deduplication disk write failed");
    } finally {
      rmSync(baseDir, { recursive: true, force: true });
    }
  });

  describe("resolveScanRepoId repository identity resolution", () => {
    it("resolves repository identity from a git directory and nested files/directories", () => {
      const gitDir = mkdtempSync(path.join(tmpdir(), "rs-git-test-"));
      try {
        const dotGit = path.join(gitDir, ".git");
        mkdirSync(dotGit, { recursive: true });
        const subDir = path.join(gitDir, "packages", "core");
        mkdirSync(subDir, { recursive: true });
        const subFile = path.join(subDir, "index.ts");
        writeFileSync(subFile, "export const x = 1;");

        const expectedRepo = path.basename(gitDir);
        expect(resolveScanRepoId(gitDir)).toBe(expectedRepo);
        expect(resolveScanRepoId(subDir)).toBe(expectedRepo);
        expect(resolveScanRepoId(subFile)).toBe(expectedRepo);
      } finally {
        rmSync(gitDir, { recursive: true, force: true });
      }
    });

    it("falls back to directory basename when no .git is found", () => {
      const plainDir = mkdtempSync(path.join(tmpdir(), "rs-plain-test-"));
      try {
        expect(resolveScanRepoId(plainDir)).toBe(path.basename(plainDir));
      } finally {
        rmSync(plainDir, { recursive: true, force: true });
      }
    });

    it("handles missing or empty paths gracefully", () => {
      expect(resolveScanRepoId("non-existent-subpath")).toBe("non-existent-subpath");
      expect(resolveScanRepoId("")).toBe("unknown-repo");
    });
  });

  describe("Deduplicated Output Verification (128 findings -> 104 unique)", () => {
    it("produces separate fingerprinted-findings.json (128) and deduplicated-findings.json (104 unique) without duplicating findings in the output", async () => {
      const baseDir = mkdtempSync(path.join(tmpdir(), "rs-128-test-"));
      const fpPath = path.join(baseDir, "fingerprinted-findings.json");
      const dedupPath = path.join(baseDir, "deduplicated-findings.json");

      try {
        // Create 104 distinct finding templates
        const uniqueTemplates: FingerprintedFinding[] = [];
        for (let i = 0; i < 104; i++) {
          uniqueTemplates.push(
            makeFinding({
              ruleId: `rule-${i}`,
              title: `Vulnerability ${i}`,
              normalizedTitle: `vulnerability-${i}`,
              filePath: `src/file-${i}.ts`,
              startLine: i + 1,
              issueFingerprint: `fp-${i}`,
            })
          );
        }

        // Add 24 duplicates (matching the first 24 templates)
        const duplicateItems: FingerprintedFinding[] = [];
        for (let i = 0; i < 24; i++) {
          duplicateItems.push({
            ...uniqueTemplates[i],
            scanner: "trivy",
          });
        }

        const all128Findings = [...uniqueTemplates, ...duplicateItems];
        expect(all128Findings).toHaveLength(128);

        // 1. Write fingerprinted-findings.json (contains all 128)
        await fs.writeFile(fpPath, JSON.stringify(all128Findings, null, 2), "utf8");

        // 2. Run deduplication
        const dedupResult = deduplicateWithStats(all128Findings);
        expect(dedupResult.totalInput).toBe(128);
        expect(dedupResult.uniqueFindings).toHaveLength(104);
        expect(dedupResult.duplicatesRemoved).toBe(24);

        // 3. Write deduplicated-findings.json
        await writeDeduplicatedFindings(dedupPath, dedupResult);

        // 4. Verify outputs
        const readFp = JSON.parse(readFileSync(fpPath, "utf8"));
        const readDedup = JSON.parse(readFileSync(dedupPath, "utf8"));

        expect(Array.isArray(readFp)).toBe(true);
        expect(readFp).toHaveLength(128);

        expect(Array.isArray(readDedup)).toBe(true);
        expect(readDedup).toHaveLength(104);

        // Verify no duplicate repoId + issueFingerprint pairs exist in final file
        const seenKeys = new Set<string>();
        for (const f of readDedup) {
          const key = `${f.repoId}::${f.issueFingerprint}`;
          expect(seenKeys.has(key)).toBe(false);
          seenKeys.add(key);
        }
        expect(seenKeys.size).toBe(104);
      } finally {
        rmSync(baseDir, { recursive: true, force: true });
      }
    });
  });
});
