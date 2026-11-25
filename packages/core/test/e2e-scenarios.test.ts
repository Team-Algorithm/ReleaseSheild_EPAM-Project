import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs/promises";
import * as fsSync from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { runScan } from "../src/scan.js";
import * as toolsModule from "../src/Scanner/tools.js";
import * as sarifModule from "../src/sarif/index.js";
import {
  readSarifFile,
  writeSarifFile,
  extractFindings,
  countFindings,
  sarifLevelToSeverity,
} from "../src/sarif/index.js";
import {
  filterFindings,
  sortFindings,
  paginateFindings,
} from "../src/findings.js";
import type {
  ToolRunner,
  ToolRunOptions,
  ToolRunOutput,
  SarifLog,
  ScanOptions,
} from "../src/types.js";

const VALID_TRIVY_REPORT: SarifLog = {
  $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "Trivy",
          rules: [{ id: "CVE-2023-9999", name: "TrivyVuln" }],
        },
      },
      results: [
        {
          ruleId: "CVE-2023-9999",
          level: "error",
          message: { text: "Critical vulnerability in dependency" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "package-lock.json" },
                region: { startLine: 45 },
              },
            },
          ],
        },
      ],
    },
  ],
};

const VALID_GITLEAKS_REPORT: SarifLog = {
  $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "gitleaks",
          rules: [{ id: "aws-secret-key", name: "AWSSecretKey" }],
        },
      },
      results: [
        {
          ruleId: "aws-secret-key",
          level: "error",
          message: { text: "AWS secret key detected" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/config.ts" },
                region: { startLine: 12 },
              },
            },
          ],
        },
      ],
    },
  ],
};

const VALID_SEMGREP_REPORT: SarifLog = {
  $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "Semgrep",
          rules: [{ id: "sqli-rule", name: "SQLInjection" }],
        },
      },
      results: [
        {
          ruleId: "sqli-rule",
          level: "error",
          message: { text: "SQL injection vulnerability" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/db.ts" },
                region: { startLine: 88 },
              },
            },
          ],
        },
      ],
    },
  ],
};

const EMPTY_VALID_TRIVY_REPORT: SarifLog = {
  $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "Trivy",
        },
      },
      results: [],
    },
  ],
};

const EMPTY_VALID_GITLEAKS_REPORT: SarifLog = {
  $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "gitleaks",
        },
      },
      results: [],
    },
  ],
};

describe("Step 9: Automated and End-to-End Test Suite", () => {
  const testOutputDir = path.resolve("./results/test-step9");
  const mergedOutputPath = path.join(testOutputDir, "result.sarif");

  const getIsolatedOptions = (overrides?: Partial<ScanOptions>): ScanOptions => ({
    outputPath: mergedOutputPath,
    sarifFiles: {
      trivy: path.join(testOutputDir, "trivy.sarif"),
      gitleaks: path.join(testOutputDir, "gitleaks.sarif"),
      semgrep: path.join(testOutputDir, "semgrep.sarif"),
    },
    ...overrides,
  });

  const cleanOutputDir = async () => {
    await fs.rm(testOutputDir, { recursive: true, force: true });
  };

  beforeEach(async () => {
    vi.restoreAllMocks();
    await cleanOutputDir();
    await fs.mkdir(testOutputDir, { recursive: true });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await cleanOutputDir();
  });

  // Scenario 1: All tools return valid reports containing findings
  it("Scenario 1: All tools return valid reports containing findings", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        const report =
          toolName === "trivy"
            ? VALID_TRIVY_REPORT
            : toolName === "gitleaks"
              ? VALID_GITLEAKS_REPORT
              : VALID_SEMGREP_REPORT;
        await fs.writeFile(options.outputPath, JSON.stringify(report), "utf-8");
        return {
          tool: toolName,
          status: "done",
          durationSec: 0.5,
          counts: { high: 1, medium: 0, low: 0 },
        };
      },
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy", "gitleaks", "semgrep"], undefined, getIsolatedOptions());

    expect(summary.tools.length).toBe(3);
    expect(summary.tools.every((t) => t.status === "done")).toBe(true);
    expect(summary.totalCounts.high).toBe(3);
    expect(summary.savedPath).toBe(mergedOutputPath);

    const merged = await readSarifFile(mergedOutputPath);
    expect(merged.runs.length).toBe(3);
    const driverNames = merged.runs.map((r) => r.tool.driver.name);
    expect(driverNames).toContain("Trivy");
    expect(driverNames).toContain("gitleaks");
    expect(driverNames).toContain("Semgrep");
  });

  // Scenario 2: All tools return valid reports containing zero findings
  it("Scenario 2: All tools return valid reports containing zero findings", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        const report =
          toolName === "trivy"
            ? EMPTY_VALID_TRIVY_REPORT
            : EMPTY_VALID_GITLEAKS_REPORT;
        await fs.writeFile(options.outputPath, JSON.stringify(report), "utf-8");
        return {
          tool: toolName,
          status: "done",
          durationSec: 0.3,
          counts: { high: 0, medium: 0, low: 0 },
        };
      },
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy", "gitleaks"], undefined, getIsolatedOptions());

    expect(summary.tools.every((t) => t.status === "done")).toBe(true);
    expect(summary.totalCounts).toEqual({ high: 0, medium: 0, low: 0 });
    expect(summary.savedPath).toBe(mergedOutputPath);

    const merged = await readSarifFile(mergedOutputPath);
    expect(merged.runs.length).toBe(2);
    expect(merged.runs[0].results?.length ?? 0).toBe(0);
    expect(merged.runs[1].results?.length ?? 0).toBe(0);
  });

  // Scenario 3: One executable is unavailable
  it("Scenario 3: One executable is unavailable while other succeeds", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => toolName !== "trivy",
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        if (toolName === "trivy") {
          return {
            tool: "trivy",
            status: "failed",
            durationSec: 0,
            counts: { high: 0, medium: 0, low: 0 },
            error: "trivy not found on PATH",
          };
        }
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        await fs.writeFile(options.outputPath, JSON.stringify(VALID_GITLEAKS_REPORT), "utf-8");
        return {
          tool: "gitleaks",
          status: "done",
          durationSec: 0.4,
          counts: { high: 1, medium: 0, low: 0 },
        };
      },
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy", "gitleaks"], undefined, getIsolatedOptions());

    const trivyResult = summary.tools.find((t) => t.tool === "trivy");
    const gitleaksResult = summary.tools.find((t) => t.tool === "gitleaks");

    expect(trivyResult?.status).toBe("failed");
    expect(trivyResult?.error).toContain("trivy not found");

    expect(gitleaksResult?.status).toBe("done");
    expect(summary.totalCounts.high).toBe(1);
    expect(summary.savedPath).toBe(mergedOutputPath);

    const merged = await readSarifFile(mergedOutputPath);
    expect(merged.runs.length).toBe(1);
    expect(merged.runs[0].tool.driver.name).toBe("gitleaks");
  });

  // Scenario 4: One tool exits unsuccessfully
  it("Scenario 4: One tool exits unsuccessfully (non-zero exit code with error output)", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        if (toolName === "gitleaks") {
          return {
            tool: "gitleaks",
            status: "failed",
            exitCode: 2,
            durationSec: 0.2,
            counts: { high: 0, medium: 0, low: 0 },
            error: "gitleaks failed (exit 2): fatal git error",
          };
        }
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        await fs.writeFile(options.outputPath, JSON.stringify(VALID_TRIVY_REPORT), "utf-8");
        return {
          tool: "trivy",
          status: "done",
          durationSec: 0.3,
          counts: { high: 1, medium: 0, low: 0 },
        };
      },
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy", "gitleaks"], undefined, getIsolatedOptions());

    expect(summary.tools.find((t) => t.tool === "gitleaks")?.status).toBe("failed");
    expect(summary.tools.find((t) => t.tool === "trivy")?.status).toBe("done");
    expect(summary.savedPath).toBe(mergedOutputPath);
  });

  // Scenario 5: One tool produces malformed JSON
  it("Scenario 5: One tool produces malformed JSON", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        if (toolName === "trivy") {
          await fs.writeFile(options.outputPath, "{\"version\": \"2.1.0\", runs: [BROKEN", "utf-8");
          return {
            tool: "trivy",
            status: "done",
            durationSec: 0.2,
            counts: { high: 1, medium: 0, low: 0 },
          };
        }
        await fs.writeFile(options.outputPath, JSON.stringify(VALID_GITLEAKS_REPORT), "utf-8");
        return {
          tool: "gitleaks",
          status: "done",
          durationSec: 0.2,
          counts: { high: 1, medium: 0, low: 0 },
        };
      },
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy", "gitleaks"], undefined, getIsolatedOptions());

    const trivyResult = summary.tools.find((t) => t.tool === "trivy");
    expect(trivyResult?.status).toBe("failed");
    expect(trivyResult?.error).toContain("Scanner did not produce a valid SARIF report");

    const gitleaksResult = summary.tools.find((t) => t.tool === "gitleaks");
    expect(gitleaksResult?.status).toBe("done");
    expect(summary.savedPath).toBe(mergedOutputPath);
  });

  // Scenario 6: One tool produces schema-invalid JSON
  it("Scenario 6: One tool produces schema-invalid JSON", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        if (toolName === "trivy") {
          // Valid JSON but invalid SARIF 2.1.0 (version 1.0.0 and missing required runs)
          await fs.writeFile(options.outputPath, JSON.stringify({ version: "1.0.0" }), "utf-8");
          return {
            tool: "trivy",
            status: "done",
            durationSec: 0.2,
            counts: { high: 1, medium: 0, low: 0 },
          };
        }
        await fs.writeFile(options.outputPath, JSON.stringify(VALID_GITLEAKS_REPORT), "utf-8");
        return {
          tool: "gitleaks",
          status: "done",
          durationSec: 0.2,
          counts: { high: 1, medium: 0, low: 0 },
        };
      },
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy", "gitleaks"], undefined, getIsolatedOptions());

    const trivyResult = summary.tools.find((t) => t.tool === "trivy");
    expect(trivyResult?.status).toBe("failed");
    expect(trivyResult?.error).toContain("Scanner did not produce a valid SARIF report");

    const gitleaksResult = summary.tools.find((t) => t.tool === "gitleaks");
    expect(gitleaksResult?.status).toBe("done");
  });

  // Scenario 7: One tool produces no report
  it("Scenario 7: One tool produces no report file at all", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        if (toolName === "trivy") {
          // Trivy does not write any file to outputPath
          return {
            tool: "trivy",
            status: "done", // runner mistakenly reported done without writing file
            durationSec: 0.1,
            counts: { high: 0, medium: 0, low: 0 },
          };
        }
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        await fs.writeFile(options.outputPath, JSON.stringify(VALID_GITLEAKS_REPORT), "utf-8");
        return {
          tool: "gitleaks",
          status: "done",
          durationSec: 0.2,
          counts: { high: 1, medium: 0, low: 0 },
        };
      },
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy", "gitleaks"], undefined, getIsolatedOptions());

    const trivyResult = summary.tools.find((t) => t.tool === "trivy");
    expect(trivyResult?.status).toBe("failed");
    expect(trivyResult?.error).toContain("Scanner did not produce a valid SARIF report");

    const gitleaksResult = summary.tools.find((t) => t.tool === "gitleaks");
    expect(gitleaksResult?.status).toBe("done");
    expect(summary.savedPath).toBe(mergedOutputPath);
  });

  // Scenario 8: One tool times out
  it("Scenario 8: One tool times out and is terminated cleanly without blocking others", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        if (toolName === "trivy") {
          return {
            tool: "trivy",
            status: "failed",
            exitCode: 1,
            durationSec: 2.0,
            counts: { high: 0, medium: 0, low: 0 },
            error: "Scan timed out after 2000ms",
          };
        }
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        await fs.writeFile(options.outputPath, JSON.stringify(VALID_GITLEAKS_REPORT), "utf-8");
        return {
          tool: "gitleaks",
          status: "done",
          durationSec: 0.3,
          counts: { high: 1, medium: 0, low: 0 },
        };
      },
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy", "gitleaks"], undefined, getIsolatedOptions());

    const trivyResult = summary.tools.find((t) => t.tool === "trivy");
    expect(trivyResult?.status).toBe("failed");
    expect(trivyResult?.error).toContain("timed out");

    const gitleaksResult = summary.tools.find((t) => t.tool === "gitleaks");
    expect(gitleaksResult?.status).toBe("done");
    expect(summary.savedPath).toBe(mergedOutputPath);
  });

  // Scenario 9: Two tools succeed while one fails
  it("Scenario 9: Two tools succeed while one fails (partial success across 3 tools)", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        if (toolName === "semgrep") {
          return {
            tool: "semgrep",
            status: "failed",
            durationSec: 0.2,
            counts: { high: 0, medium: 0, low: 0 },
            error: "Semgrep binary crashed",
          };
        }
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        const report =
          toolName === "trivy" ? VALID_TRIVY_REPORT : VALID_GITLEAKS_REPORT;
        await fs.writeFile(options.outputPath, JSON.stringify(report), "utf-8");
        return {
          tool: toolName,
          status: "done",
          durationSec: 0.3,
          counts: { high: 1, medium: 0, low: 0 },
        };
      },
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy", "gitleaks", "semgrep"], undefined, getIsolatedOptions());

    expect(summary.tools.find((t) => t.tool === "semgrep")?.status).toBe("failed");
    expect(summary.tools.find((t) => t.tool === "trivy")?.status).toBe("done");
    expect(summary.tools.find((t) => t.tool === "gitleaks")?.status).toBe("done");
    expect(summary.totalCounts.high).toBe(2);
    expect(summary.savedPath).toBe(mergedOutputPath);

    const merged = await readSarifFile(mergedOutputPath);
    expect(merged.runs.length).toBe(2);
  });

  // Scenario 10: Every tool fails
  it("Scenario 10: Every tool fails, resulting in zero findings and no report saved", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (): Promise<ToolRunOutput> => ({
        tool: toolName,
        status: "failed",
        durationSec: 0.1,
        counts: { high: 0, medium: 0, low: 0 },
        error: `${toolName} execution error`,
      }),
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy", "gitleaks"], undefined, getIsolatedOptions());

    expect(summary.tools.every((t) => t.status === "failed")).toBe(true);
    expect(summary.totalCounts).toEqual({ high: 0, medium: 0, low: 0 });
    expect(summary.savedPath).toBe("");

    const exists = fsSync.existsSync(mergedOutputPath);
    expect(exists).toBe(false);
  });

  // Scenario 11: Final merged output fails schema validation
  it("Scenario 11: Final merged output fails schema validation and fails gracefully", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        await fs.writeFile(options.outputPath, JSON.stringify(VALID_TRIVY_REPORT), "utf-8");
        return {
          tool: toolName,
          status: "done",
          durationSec: 0.2,
          counts: { high: 1, medium: 0, low: 0 },
        };
      },
    } as unknown as ToolRunner));

    // Force writeSarifFile validation failure by injecting an invalid merger response
    vi.spyOn(sarifModule, "mergeSarif").mockReturnValue({
      version: "1.0.0", // schema invalid version
      runs: [],
    } as unknown as SarifLog);

    const summary = await runScan(["trivy"], undefined, getIsolatedOptions());

    expect(summary.savedPath).toBe("");
    expect(summary.tools[0].status).toBe("failed");
    expect(summary.tools[0].error).toContain("Failed to merge or save SARIF");
    expect(fsSync.existsSync(mergedOutputPath)).toBe(false);
  });

  // Scenario 12: Writing the final report fails
  it("Scenario 12: Writing final report fails on disk I/O without leaving misleading files", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        await fs.writeFile(options.outputPath, JSON.stringify(VALID_TRIVY_REPORT), "utf-8");
        return {
          tool: toolName,
          status: "done",
          durationSec: 0.2,
          counts: { high: 1, medium: 0, low: 0 },
        };
      },
    } as unknown as ToolRunner));

    vi.spyOn(sarifModule, "writeSarifFile").mockRejectedValue(new Error("ENOSPC: no space left on device"));

    const summary = await runScan(["trivy"], undefined, getIsolatedOptions());

    expect(summary.savedPath).toBe("");
    expect(summary.tools[0].status).toBe("failed");
    expect(summary.tools[0].error).toContain("ENOSPC");
    expect(fsSync.existsSync(mergedOutputPath)).toBe(false);
  });

  // Scenario 13: A previous valid report exists and the next scan fails
  it("Scenario 13: Pre-existing valid report is cleaned up and not published when next scan fails", async () => {
    // Write an existing report from a prior run
    await fs.writeFile(mergedOutputPath, JSON.stringify(VALID_TRIVY_REPORT), "utf-8");
    expect(fsSync.existsSync(mergedOutputPath)).toBe(true);

    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (): Promise<ToolRunOutput> => ({
        tool: toolName,
        status: "failed",
        durationSec: 0.1,
        counts: { high: 0, medium: 0, low: 0 },
        error: "Fatal scanner crash",
      }),
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy"], undefined, getIsolatedOptions());

    expect(summary.savedPath).toBe("");
    // The pre-existing file MUST have been deleted at the start of the scan
    expect(fsSync.existsSync(mergedOutputPath)).toBe(false);
  });

  // Scenario 14: Optional locations or line numbers are absent
  it("Scenario 14: Handles absent optional locations or line numbers gracefully", () => {
    const reportWithoutLocations: SarifLog = {
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "trivy" } },
          results: [
            {
              ruleId: "CVE-2023-0001",
              level: "error",
              message: { text: "Location-less vulnerability" },
              // locations omitted
            },
            {
              ruleId: "CVE-2023-0002",
              level: "warning",
              message: { text: "Location without region" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "Dockerfile" },
                    // region omitted
                  },
                },
              ],
            },
          ],
        },
      ],
    };

    const findings = extractFindings(reportWithoutLocations);
    expect(findings.length).toBe(2);

    expect(findings[0].location).toBe("unknown");
    expect(findings[0].line).toBeUndefined();

    expect(findings[1].location).toBe("Dockerfile");
    expect(findings[1].line).toBeUndefined();

    const counts = countFindings(reportWithoutLocations);
    expect(counts).toEqual({ high: 1, medium: 1, low: 0 });
  });

  // Scenario 15: Severity and rule-level defaults are handled correctly
  it("Scenario 15: Severity and rule-level defaults are handled correctly", () => {
    // 1. Level-based fallback
    expect(sarifLevelToSeverity("error")).toBe("high");
    expect(sarifLevelToSeverity("warning")).toBe("medium");
    expect(sarifLevelToSeverity("note")).toBe("low");
    expect(sarifLevelToSeverity("none")).toBe("low");
    expect(sarifLevelToSeverity(undefined)).toBe("medium"); // default fallback

    // 2. Score thresholds (security-severity property)
    expect(sarifLevelToSeverity("warning", 9.5)).toBe("high");
    expect(sarifLevelToSeverity("note", 7.0)).toBe("high");
    expect(sarifLevelToSeverity("error", 6.9)).toBe("medium");
    expect(sarifLevelToSeverity("note", 4.0)).toBe("medium");
    expect(sarifLevelToSeverity("error", 3.9)).toBe("low");
    expect(sarifLevelToSeverity("warning", 0.0)).toBe("low");

    // 3. Rule metadata fallback (result level missing, falls back to rule defaultConfiguration.level)
    const ruleFallbackReport: SarifLog = {
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "gitleaks",
              rules: [
                {
                  id: "rule-error",
                  defaultConfiguration: { level: "error" },
                },
                {
                  id: "rule-score",
                  properties: { "security-severity": "8.5" },
                },
              ],
            },
          },
          results: [
            {
              ruleId: "rule-error",
              // level omitted -> rule defaultConfiguration.level: error -> high
              message: { text: "Rule default error" },
            },
            {
              ruleId: "rule-score",
              // level and secSev omitted -> rule security-severity: 8.5 -> high
              message: { text: "Rule default score" },
            },
          ],
        },
      ],
    };

    const findings = extractFindings(ruleFallbackReport);
    expect(findings[0].severity).toBe("high");
    expect(findings[1].severity).toBe("high");
  });

  // Scenario 16: Old reports cannot be mistaken for current output
  it("Scenario 16: Old reports cannot be mistaken for current output across individual and merged paths", async () => {
    const staleTrivyFile = path.join(testOutputDir, "trivy.sarif");
    await fs.writeFile(staleTrivyFile, "old trivy output", "utf-8");
    await fs.writeFile(mergedOutputPath, "old merged output", "utf-8");

    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        // Purges stale report and writes fresh one
        await fs.rm(options.outputPath, { force: true });
        await fs.writeFile(options.outputPath, JSON.stringify(VALID_TRIVY_REPORT), "utf-8");
        return {
          tool: toolName,
          status: "done",
          durationSec: 0.2,
          counts: { high: 1, medium: 0, low: 0 },
        };
      },
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy"], undefined, {
      outputPath: mergedOutputPath,
      sarifFiles: {
        trivy: staleTrivyFile,
        gitleaks: path.join(testOutputDir, "gitleaks.sarif"),
        semgrep: path.join(testOutputDir, "semgrep.sarif"),
      },
    });

    expect(summary.savedPath).toBe(mergedOutputPath);
    const content = await fs.readFile(mergedOutputPath, "utf-8");
    expect(content).not.toBe("old merged output");
    const parsed = JSON.parse(content);
    expect(parsed.version).toBe("2.1.0");
  });

  // Scenario 17: Existing filters, sorting, pagination, and exports relying on SARIF functions still work
  it("Scenario 17: Existing filters, sorting, pagination, and exports relying on SARIF functions still work", () => {
    const rawFindings = extractFindings(VALID_TRIVY_REPORT);
    expect(rawFindings.length).toBe(1);

    const testFindings = [
      ...rawFindings,
      ...extractFindings(VALID_GITLEAKS_REPORT),
      ...extractFindings(VALID_SEMGREP_REPORT),
    ];
    expect(testFindings.length).toBe(3);

    // Filters
    const filteredTrivy = filterFindings(testFindings, { tool: "trivy" });
    expect(filteredTrivy.length).toBe(1);
    expect(filteredTrivy[0].tool).toBe("trivy");

    const filteredHigh = filterFindings(testFindings, { severity: "high" });
    expect(filteredHigh.length).toBe(3);

    // Sorting
    const sorted = sortFindings([...testFindings], "tool");
    expect(sorted.map((f) => f.tool)).toEqual(["gitleaks", "semgrep", "trivy"]);

    // Pagination
    const page1 = paginateFindings(testFindings, 1, 2);
    expect(page1.currentPage).toBe(1);
    expect(page1.totalPages).toBe(2);
    expect(page1.findings.length).toBe(2);

    const page2 = paginateFindings(testFindings, 2, 2);
    expect(page2.currentPage).toBe(2);
    expect(page2.findings.length).toBe(1);
  });

  // Scenario 18: No imports or references depend on the deleted src/sarif.ts
  it("Scenario 18: No imports or references depend on the deleted src/sarif.ts across the codebase", async () => {
    const coreIndex = await fs.readFile(
      path.resolve(fileURLToPath(import.meta.url), "../../src/index.ts"),
      "utf-8"
    );
    expect(coreIndex).not.toContain("./sarif.js");
    expect(coreIndex).toContain("./sarif/index.js");

    // Verify deleted file is really gone
    const oldFilePath = path.resolve(fileURLToPath(import.meta.url), "../../src/sarif.ts");
    expect(fsSync.existsSync(oldFilePath)).toBe(false);
  });

  // Scenario 19: New module exports work from their actual callers
  it("Scenario 19: New module exports work from their actual callers", async () => {
    // Check that core public exports expose all expected members from sarif modules
    const core = await import("../src/index.js");

    expect(typeof core.runScan).toBe("function");
    expect(typeof core.validateSarif).toBe("function");
    expect(typeof core.validateSarifDetailed).toBe("function");
    expect(typeof core.assertValidSarif).toBe("function");
    expect(typeof core.parseSarif).toBe("function");
    expect(typeof core.readSarifFile).toBe("function");
    expect(typeof core.writeSarifFile).toBe("function");
    expect(typeof core.mergeSarif).toBe("function");
    expect(typeof core.extractFindings).toBe("function");
    expect(typeof core.countFindings).toBe("function");
    expect(typeof core.sarifLevelToSeverity).toBe("function");
    expect(typeof core.buildSummary).toBe("function");
    expect(typeof core.filterFindings).toBe("function");
    expect(typeof core.sortFindings).toBe("function");
    expect(typeof core.paginateFindings).toBe("function");
  });
});
