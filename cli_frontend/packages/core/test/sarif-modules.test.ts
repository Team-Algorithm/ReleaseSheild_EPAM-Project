import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import {
  parseSarif,
  readSarifFile,
  writeSarifFile,
  sarifLevelToSeverity,
  countFindings,
  extractFindings,
  normalizeToolName,
  mergeSarif,
  buildSummary,
  SarifExtractionError,
  SarifMergeError,
} from "../src/sarif/index.js";
import type { SarifLog } from "../types.js";

describe("SARIF Modular Architecture (parser, findings, merger)", () => {
  const tmpDir = path.join(process.cwd(), ".tmp-test-sarif-modules");

  beforeEach(async () => {
    await fs.mkdir(tmpDir, { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  const validReport: SarifLog = {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "trivy",
            rules: [
              {
                id: "CVE-2023-1234",
                properties: { "security-severity": "9.1" },
              },
            ],
          },
        },
        results: [
          {
            ruleId: "CVE-2023-1234",
            level: "error",
            message: { text: "Critical vulnerability" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "package.json" },
                  region: { startLine: 10 },
                },
              },
            ],
          },
        ],
      },
    ],
  };

  describe("Parser & File I/O (parser.ts)", () => {
    it("parses valid SARIF JSON string", () => {
      const raw = JSON.stringify(validReport);
      const parsed = parseSarif(raw);
      expect(parsed.version).toBe("2.1.0");
      expect(parsed.runs.length).toBe(1);
    });

    it("distinguishes JSON syntax errors from schema validation errors", () => {
      expect(() => parseSarif("invalid { json")).toThrow(/Failed to parse SARIF JSON/);
      expect(() => parseSarif('{"version": "1.0.0"}')).toThrow(/Invalid SARIF 2.1.0 structure/);
    });

    it("reads and parses valid SARIF file from disk", async () => {
      const targetPath = path.join(tmpDir, "report.sarif");
      await fs.writeFile(targetPath, JSON.stringify(validReport), "utf-8");

      const loaded = await readSarifFile(targetPath);
      expect(loaded.version).toBe("2.1.0");
      expect(loaded.runs[0].tool.driver.name).toBe("trivy");
    });

    it("preserves filesystem errors (e.g. ENOENT) on missing file", async () => {
      const missingPath = path.join(tmpDir, "non-existent.sarif");
      await expect(readSarifFile(missingPath)).rejects.toThrow(/ENOENT/);
    });

    it("atomically writes valid SARIF file, creating directories recursively", async () => {
      const nestedPath = path.join(tmpDir, "deeply", "nested", "result.sarif");
      await writeSarifFile(nestedPath, validReport);

      const content = await fs.readFile(nestedPath, "utf-8");
      expect(JSON.parse(content).version).toBe("2.1.0");
    });

    it("rejects invalid SARIF without leaving partial files", async () => {
      const invalidPath = path.join(tmpDir, "invalid.sarif");
      const badReport = { version: "1.0.0" } as unknown as SarifLog;

      await expect(writeSarifFile(invalidPath, badReport)).rejects.toThrow();
      const exists = await fs
        .access(invalidPath)
        .then(() => true)
        .catch(() => false);
      expect(exists).toBe(false);
    });
  });

  describe("Findings Extraction & Normalization (findings.ts)", () => {
    it("correctly identifies tool drivers without defaulting unknown to Trivy", () => {
      expect(normalizeToolName("Trivy Scanner")).toBe("trivy");
      expect(normalizeToolName("Gitleaks")).toBe("gitleaks");
      expect(normalizeToolName("Semgrep-Core")).toBe("semgrep");
      expect(normalizeToolName("Bandit")).toBeUndefined();
      expect(normalizeToolName("UnknownScanner")).toBeUndefined();
    });

    it("throws SarifExtractionError when encountering an unsupported tool driver", () => {
      const unknownDriverReport: SarifLog = {
        version: "2.1.0",
        runs: [
          {
            tool: { driver: { name: "custom-unsupported-tool" } },
            results: [],
          },
        ],
      };

      expect(() => extractFindings(unknownDriverReport)).toThrow(SarifExtractionError);
      expect(() => extractFindings(unknownDriverReport)).toThrow(/Unsupported tool driver/);
    });

    it("extracts findings and counts with strict parity", () => {
      const findings = extractFindings(validReport);
      const counts = countFindings(validReport);

      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe("high");
      expect(findings[0].tool).toBe("trivy");
      expect(counts).toEqual({ high: 1, medium: 0, low: 0 });
    });
  });

  describe("Merger & Summaries (merger.ts)", () => {
    it("merges multiple valid reports preserving all runs", () => {
      const gitleaksReport: SarifLog = {
        version: "2.1.0",
        runs: [
          {
            tool: { driver: { name: "gitleaks" } },
            results: [],
          },
        ],
      };

      const merged = mergeSarif([validReport, gitleaksReport]);
      expect(merged.runs.length).toBe(2);
      expect(merged.runs[0].tool.driver.name).toBe("trivy");
      expect(merged.runs[1].tool.driver.name).toBe("gitleaks");
    });

    it("throws SarifMergeError on invalid input instead of silently discarding it", () => {
      const invalidReport = { version: "1.0.0" } as unknown as SarifLog;
      expect(() => mergeSarif([validReport, invalidReport])).toThrow(SarifMergeError);
      try {
        mergeSarif([validReport, invalidReport]);
      } catch (err) {
        expect(err).toBeInstanceOf(SarifMergeError);
        const mergeErr = err as SarifMergeError;
        expect(mergeErr.reportIndex).toBe(1);
        expect(mergeErr.message).toContain("Cannot merge invalid SARIF document at index 1");
      }
    });

    it("builds summary calculating total counts and max duration", () => {
      const summary = buildSummary([
        {
          tool: "trivy",
          status: "done",
          durationSec: 12.5,
          counts: { high: 2, medium: 1, low: 0 },
        },
        {
          tool: "gitleaks",
          status: "done",
          durationSec: 5.2,
          counts: { high: 1, medium: 0, low: 3 },
        },
      ]);

      expect(summary.totalCounts).toEqual({ high: 3, medium: 1, low: 3 });
      expect(summary.totalDurationSec).toBe(12.5);
      expect(summary.savedPath).toBe("./results/result.sarif");
    });
  });
});
