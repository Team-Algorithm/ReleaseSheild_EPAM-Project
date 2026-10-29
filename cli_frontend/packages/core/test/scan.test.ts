import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { runScan, TOOL_CONFIGS } from "../src/scan.js";
import * as toolsModule from "../src/Scanner/tools.js";
import * as sarifModule from "../src/sarif/index.js";
import { readSarifFile } from "../src/sarif/parser.js";
import type { ToolUpdate, ToolRunner, ToolRunOptions, ToolRunOutput } from "../src/types.js";

const VALID_TRIVY_SARIF = {
  $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "Trivy",
          rules: [{ id: "CVE-2023-1234", name: "SecurityVulnerability" }]
        }
      },
      results: [
        {
          ruleId: "CVE-2023-1234",
          level: "error",
          message: { text: "High severity vulnerability found" }
        }
      ]
    }
  ]
};

const VALID_GITLEAKS_SARIF = {
  $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "gitleaks",
          rules: [{ id: "generic-api-key", name: "GenericApiKey" }]
        }
      },
      results: [
        {
          ruleId: "generic-api-key",
          level: "error",
          message: { text: "Hardcoded secret detected" }
        }
      ]
    }
  ]
};

describe("runScan Engine", () => {
  const resultSarifPath = path.resolve("./results/result.sarif");
  const trivySarifPath = path.resolve("./results/trivy.sarif");
  const gitleaksSarifPath = path.resolve("./results/gitleaks.sarif");

  const cleanFiles = async () => {
    await fs.rm(resultSarifPath, { force: true });
    await fs.rm(trivySarifPath, { force: true });
    await fs.rm(gitleaksSarifPath, { force: true });
  };

  beforeEach(async () => {
    vi.restoreAllMocks();
    await cleanFiles();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await cleanFiles();
  });

  it("returns empty summary with empty savedPath immediately if no tools provided", async () => {
    const summary = await runScan([]);
    expect(summary.tools).toEqual([]);
    expect(summary.totalDurationSec).toBe(0);
    expect(summary.totalCounts).toEqual({ high: 0, medium: 0, low: 0 });
    expect(summary.savedPath).toBe("");
  });

  it("runs selected tools in parallel with speedMultiplier (simulation)", async () => {
    const updates: ToolUpdate[] = [];
    const summary = await runScan(
      ["trivy", "gitleaks"],
      (u) => updates.push(u),
      { speedMultiplier: 200 }
    );

    expect(summary.tools.length).toBe(2);

    const trivy = summary.tools.find((t) => t.tool === "trivy");
    const gitleaks = summary.tools.find((t) => t.tool === "gitleaks");

    expect(trivy?.status).toBe("done");
    expect(trivy?.counts).toEqual(TOOL_CONFIGS.trivy.counts);
    expect(trivy?.durationSec).toBe(TOOL_CONFIGS.trivy.durationSec);

    expect(gitleaks?.status).toBe("done");
    expect(gitleaks?.counts).toEqual(TOOL_CONFIGS.gitleaks.counts);
    expect(gitleaks?.durationSec).toBe(TOOL_CONFIGS.gitleaks.durationSec);

    expect(summary.totalDurationSec).toBe(TOOL_CONFIGS.trivy.durationSec);
    expect(summary.totalCounts.high).toBe(
      TOOL_CONFIGS.trivy.counts.high + TOOL_CONFIGS.gitleaks.counts.high
    );
    expect(summary.savedPath).toBe("./results/result.sarif");

    expect(updates.length).toBeGreaterThan(0);
    expect(updates.some((u) => u.tool === "trivy" && u.status === "running")).toBe(true);
    expect(updates.some((u) => u.tool === "trivy" && u.status === "done")).toBe(true);
  });

  it("simulates tool failure when failTool is provided without stopping other tools", async () => {
    const summary = await runScan(["trivy", "gitleaks"], undefined, {
      failTool: "gitleaks",
      speedMultiplier: 200
    });

    const trivy = summary.tools.find((t) => t.tool === "trivy");
    const gitleaks = summary.tools.find((t) => t.tool === "gitleaks");

    expect(trivy?.status).toBe("done");
    expect(trivy?.counts.high).toBe(TOOL_CONFIGS.trivy.counts.high);

    expect(gitleaks?.status).toBe("failed");
    expect(gitleaks?.error).toBe("gitleaks not found");
    expect(gitleaks?.counts).toEqual({ high: 0, medium: 0, low: 0 });

    expect(summary.totalCounts.high).toBe(TOOL_CONFIGS.trivy.counts.high);
    expect(summary.savedPath).toBe("./results/result.sarif");
  });

  it("returns empty savedPath in simulation when all tools fail", async () => {
    const summary = await runScan(["trivy"], undefined, {
      failTool: "trivy",
      speedMultiplier: 200
    });

    expect(summary.tools[0].status).toBe("failed");
    expect(summary.savedPath).toBe("");
  });

  it("stops timers and resolves when abortSignal is triggered", async () => {
    const controller = new AbortController();

    const scanPromise = runScan(["semgrep"], undefined, {
      abortSignal: controller.signal,
      speedMultiplier: 5
    });

    setTimeout(() => controller.abort(), 50);

    const summary = await scanPromise;
    expect(summary.tools.length).toBe(1);
    expect(summary.tools[0].status).toBe("failed");
    expect(summary.tools[0].error).toBe("Scan cancelled");
    expect(summary.savedPath).toBe("");
  });

  it("handles total failure in production when scanners fail (no fake report written)", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => false,
      buildArgs: () => [],
      run: async (_options: ToolRunOptions): Promise<ToolRunOutput> => ({
        tool: toolName,
        status: "failed",
        durationSec: 0.1,
        counts: { high: 0, medium: 0, low: 0 },
        error: `${toolName} binary not found`
      })
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy", "gitleaks"]);

    expect(summary.tools.length).toBe(2);
    expect(summary.tools.every((t) => t.status === "failed")).toBe(true);
    expect(summary.totalCounts).toEqual({ high: 0, medium: 0, low: 0 });
    expect(summary.savedPath).toBe("");

    // Verify result.sarif was not created
    const fileExists = await fs.access(resultSarifPath).then(() => true).catch(() => false);
    expect(fileExists).toBe(false);
  });

  it("runs Trivy and Gitleaks concurrently with independent failure handling (partial success)", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        if (toolName === "trivy") {
          await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
          await fs.writeFile(options.outputPath, JSON.stringify(VALID_TRIVY_SARIF), "utf-8");
          return {
            tool: "trivy",
            status: "done",
            durationSec: 0.2,
            counts: { high: 1, medium: 0, low: 0 }
          };
        }
        return {
          tool: "gitleaks",
          status: "failed",
          durationSec: 0.1,
          counts: { high: 0, medium: 0, low: 0 },
          error: "Gitleaks process crashed"
        };
      }
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy", "gitleaks"]);

    const trivy = summary.tools.find((t) => t.tool === "trivy");
    const gitleaks = summary.tools.find((t) => t.tool === "gitleaks");

    expect(trivy?.status).toBe("done");
    expect(trivy?.counts.high).toBe(1);

    expect(gitleaks?.status).toBe("failed");
    expect(gitleaks?.error).toBe("Gitleaks process crashed");

    expect(summary.totalCounts.high).toBe(1);
    expect(summary.savedPath).toBe("./results/result.sarif");

    // Check merged report contains only Trivy run
    const merged = await readSarifFile(resultSarifPath);
    expect(merged.runs.length).toBe(1);
    expect(merged.runs[0].tool.driver.name).toBe("Trivy");
  });

  it("merges all reports when Trivy and Gitleaks both succeed", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        if (toolName === "trivy") {
          await fs.writeFile(options.outputPath, JSON.stringify(VALID_TRIVY_SARIF), "utf-8");
          return {
            tool: "trivy",
            status: "done",
            durationSec: 0.3,
            counts: { high: 1, medium: 0, low: 0 }
          };
        } else {
          await fs.writeFile(options.outputPath, JSON.stringify(VALID_GITLEAKS_SARIF), "utf-8");
          return {
            tool: "gitleaks",
            status: "done",
            durationSec: 0.2,
            counts: { high: 1, medium: 0, low: 0 }
          };
        }
      }
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy", "gitleaks"]);

    expect(summary.tools.every((t) => t.status === "done")).toBe(true);
    expect(summary.totalCounts.high).toBe(2);
    expect(summary.savedPath).toBe("./results/result.sarif");

    const merged = await readSarifFile(resultSarifPath);
    expect(merged.runs.length).toBe(2);
    const driverNames = merged.runs.map((r) => r.tool.driver.name);
    expect(driverNames).toContain("Trivy");
    expect(driverNames).toContain("gitleaks");
  });

  it("marks scanner failed when output SARIF is invalid/corrupt and does not corrupt clean scans", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        if (toolName === "trivy") {
          // Corrupt JSON output
          await fs.writeFile(options.outputPath, "NOT_JSON{{{", "utf-8");
          return {
            tool: "trivy",
            status: "done",
            durationSec: 0.1,
            counts: { high: 5, medium: 0, low: 0 }
          };
        } else {
          await fs.writeFile(options.outputPath, JSON.stringify(VALID_GITLEAKS_SARIF), "utf-8");
          return {
            tool: "gitleaks",
            status: "done",
            durationSec: 0.2,
            counts: { high: 1, medium: 0, low: 0 }
          };
        }
      }
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy", "gitleaks"]);

    const trivy = summary.tools.find((t) => t.tool === "trivy");
    const gitleaks = summary.tools.find((t) => t.tool === "gitleaks");

    // Trivy should be converted to failed due to corrupted SARIF
    expect(trivy?.status).toBe("failed");
    expect(trivy?.error).toContain("Scanner did not produce a valid SARIF report");
    expect(trivy?.counts).toEqual({ high: 0, medium: 0, low: 0 });

    // Gitleaks should remain successful
    expect(gitleaks?.status).toBe("done");
    expect(gitleaks?.counts.high).toBe(1);

    expect(summary.totalCounts.high).toBe(1);
    expect(summary.savedPath).toBe("./results/result.sarif");

    const merged = await readSarifFile(resultSarifPath);
    expect(merged.runs.length).toBe(1);
    expect(merged.runs[0].tool.driver.name).toBe("gitleaks");
  });

  it("publishes to custom outputPath and cleans up only the intended target", async () => {
    const customDir = path.resolve("./results/custom-output-test");
    const customReportPath = path.join(customDir, "custom-result.sarif");
    const unrelatedReportPath = path.resolve("./results/unrelated-keeper.sarif");

    await fs.mkdir(customDir, { recursive: true });
    await fs.writeFile(customReportPath, "stale-custom-data", "utf-8");
    await fs.writeFile(unrelatedReportPath, "unrelated-preserved-data", "utf-8");

    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        await fs.writeFile(options.outputPath, JSON.stringify(VALID_TRIVY_SARIF), "utf-8");
        return {
          tool: "trivy",
          status: "done",
          durationSec: 0.2,
          counts: { high: 1, medium: 0, low: 0 }
        };
      }
    } as unknown as ToolRunner));

    const summary = await runScan(["trivy"], undefined, {
      outputPath: customReportPath
    });

    expect(summary.savedPath).toBe(customReportPath);
    expect(summary.tools[0].status).toBe("done");

    // Merged report was written to customReportPath
    const merged = await readSarifFile(customReportPath);
    expect(merged.runs.length).toBe(1);
    expect(merged.runs[0].tool.driver.name).toBe("Trivy");

    // Unrelated file was preserved untouched
    const unrelatedContent = await fs.readFile(unrelatedReportPath, "utf-8");
    expect(unrelatedContent).toBe("unrelated-preserved-data");

    // Standard result.sarif was not created
    const defaultExists = await fs.access(resultSarifPath).then(() => true).catch(() => false);
    expect(defaultExists).toBe(false);

    // Clean up
    await fs.rm(customDir, { recursive: true, force: true });
    await fs.rm(unrelatedReportPath, { force: true });
  });

  it("handles publication write failure safely without leaving misleading reports", async () => {
    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        await fs.writeFile(options.outputPath, JSON.stringify(VALID_TRIVY_SARIF), "utf-8");
        return {
          tool: "trivy",
          status: "done",
          durationSec: 0.2,
          counts: { high: 1, medium: 0, low: 0 }
        };
      }
    } as unknown as ToolRunner));

    // Mock writeSarifFile to simulate a filesystem/permission failure during publication
    vi.spyOn(sarifModule, "writeSarifFile").mockRejectedValue(new Error("EACCES: permission denied"));

    const summary = await runScan(["trivy"]);

    // savedPath must be empty string
    expect(summary.savedPath).toBe("");
    // Successful tools must be converted to failed with the publication error
    expect(summary.tools[0].status).toBe("failed");
    expect(summary.tools[0].error).toContain("Failed to merge or save SARIF");
    expect(summary.tools[0].error).toContain("permission denied");

    // No file must exist at resultSarifPath
    const exists = await fs.access(resultSarifPath).then(() => true).catch(() => false);
    expect(exists).toBe(false);
  });
});
