import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs/promises";
import * as path from "path";
import {
  validateSarif,
  parseSarif,
  sarifLevelToSeverity,
  countFindings,
  extractFindings,
  mergeSarif,
  buildSummary,
  readSarifFile,
  writeSarifFile,
} from "../src/sarif.js";
import type { SarifLog } from "../src/types.js";

describe("SARIF Ingestion & Processing Layer", () => {
  const tmpDir = path.join(process.cwd(), ".tmp-test-sarif");

  beforeEach(async () => {
    await fs.mkdir(tmpDir, { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  const validSampleSarif: SarifLog = {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "semgrep",
            rules: [
              {
                id: "sec.sqli",
                properties: { "security-severity": "8.9" },
              },
              {
                id: "sec.xss",
                properties: { "security-severity": "5.4" },
              },
              {
                id: "sec.info",
                properties: { "security-severity": "2.1" },
              },
            ],
          },
        },
        results: [
          {
            ruleId: "sec.sqli",
            level: "error",
            message: { text: "SQL injection detected" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "controllers/search.py" },
                  region: { startLine: 42 },
                },
              },
            ],
          },
          {
            ruleId: "sec.xss",
            level: "warning",
            message: { text: "Potential XSS in template" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "views/profile.html" },
                  region: { startLine: 18 },
                },
              },
            ],
          },
          {
            ruleId: "sec.info",
            level: "note",
            message: { text: "Informational note" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "app.js" },
                  region: { startLine: 5 },
                },
              },
            ],
          },
        ],
      },
    ],
  };

  it("validates standard SARIF 2.1.0 document", () => {
    expect(validateSarif(validSampleSarif)).toBe(true);
    expect(validateSarif(null)).toBe(false);
    expect(validateSarif({})).toBe(false);
    expect(validateSarif({ version: "1.0.0", runs: [] })).toBe(false);
    expect(validateSarif({ version: "2.1.0", runs: "not-array" })).toBe(false);
    expect(validateSarif({ version: "2.1.0", runs: [{ tool: {} }] })).toBe(
      false,
    );
  });

  it("parses valid JSON string into SarifLog", () => {
    const raw = JSON.stringify(validSampleSarif);
    const parsed = parseSarif(raw);
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs.length).toBe(1);
  });

  it("throws on invalid SARIF JSON", () => {
    expect(() => parseSarif("{ invalid json")).toThrow(
      /Failed to parse SARIF JSON/,
    );
    expect(() => parseSarif('{"version": "1.0"}')).toThrow(
      /Invalid SARIF 2.1.0 structure/,
    );
  });

  it("converts SARIF levels and CVSS security-severity scores properly", () => {
    // Numeric scores
    expect(sarifLevelToSeverity("note", 8.5)).toBe("high");
    expect(sarifLevelToSeverity("note", 5.0)).toBe("medium");
    expect(sarifLevelToSeverity("error", 2.0)).toBe("low");

    // Standard fallback by level
    expect(sarifLevelToSeverity("error")).toBe("high");
    expect(sarifLevelToSeverity("warning")).toBe("medium");
    expect(sarifLevelToSeverity("note")).toBe("low");
    expect(sarifLevelToSeverity("none")).toBe("low");
  });

  it("counts findings by severity across runs", () => {
    const counts = countFindings(validSampleSarif);
    expect(counts).toEqual({ high: 1, medium: 1, low: 1 });
  });

  it("extracts normalized findings for UI and triage", () => {
    const findings = extractFindings(validSampleSarif);
    expect(findings.length).toBe(3);

    expect(findings[0]).toEqual({
      tool: "semgrep",
      rule: "sec.sqli",
      severity: "high",
      location: "controllers/search.py",
      line: 42,
      message: "SQL injection detected",
    });

    expect(findings[1].severity).toBe("medium");
    expect(findings[2].severity).toBe("low");
  });

  it("filters extracted findings by tool", () => {
    const semgrepFindings = extractFindings(validSampleSarif, "semgrep");
    expect(semgrepFindings.length).toBe(3);

    const trivyFindings = extractFindings(validSampleSarif, "trivy");
    expect(trivyFindings.length).toBe(0);
  });

  it("merges multiple SARIF logs into a single valid document", () => {
    const trivySarif: SarifLog = {
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "trivy" } },
          results: [],
        },
      ],
    };

    const merged = mergeSarif([validSampleSarif, trivySarif]);
    expect(merged.version).toBe("2.1.0");
    expect(merged.runs.length).toBe(2);
    expect(merged.runs[0].tool.driver.name).toBe("semgrep");
    expect(merged.runs[1].tool.driver.name).toBe("trivy");
  });

  it("builds summary and calculates total counts and duration", () => {
    const summary = buildSummary([
      {
        tool: "trivy",
        status: "done",
        durationSec: 10.5,
        counts: { high: 2, medium: 3, low: 1 },
      },
      {
        tool: "semgrep",
        status: "done",
        durationSec: 15.2,
        counts: { high: 1, medium: 0, low: 2 },
      },
    ]);

    expect(summary.totalCounts).toEqual({ high: 3, medium: 3, low: 3 });
    expect(summary.totalDurationSec).toBe(15.2);
    expect(summary.savedPath).toBe("./results/result.sarif");
  });

  it("reads and writes SARIF files from disk", async () => {
    const testFile = path.join(tmpDir, "test.sarif");
    await writeSarifFile(testFile, validSampleSarif);

    const loaded = await readSarifFile(testFile);
    expect(loaded.version).toBe("2.1.0");
    expect(loaded.runs.length).toBe(1);
    expect(loaded.runs[0].tool.driver.name).toBe("semgrep");
  });
});
