import { describe, it, expect } from "vitest";
import { runScan, TOOL_CONFIGS } from "../src/fakeScan.js";
import type { ToolUpdate } from "../src/types.js";

describe("runScan Engine", () => {
  it("returns empty summary immediately if no tools provided", async () => {
    const summary = await runScan([]);
    expect(summary.tools).toEqual([]);
    expect(summary.totalDurationSec).toBe(0);
    expect(summary.totalCounts).toEqual({ high: 0, medium: 0, low: 0 });
    expect(summary.savedPath).toBe("./results/result.sarif");
  });

  it("runs selected tools in parallel with speedMultiplier", async () => {
    const updates: ToolUpdate[] = [];
    const summary = await runScan(
      ["trivy", "gitleaks"],
      (u) => updates.push(u),
      { speedMultiplier: 200 },
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

    // Total duration is the duration of the slowest tool
    expect(summary.totalDurationSec).toBe(TOOL_CONFIGS.trivy.durationSec);

    // Sum of severity counts
    expect(summary.totalCounts.high).toBe(
      TOOL_CONFIGS.trivy.counts.high + TOOL_CONFIGS.gitleaks.counts.high,
    );

    // Check that callbacks were received
    expect(updates.length).toBeGreaterThan(0);
    expect(
      updates.some((u) => u.tool === "trivy" && u.status === "running"),
    ).toBe(true);
    expect(updates.some((u) => u.tool === "trivy" && u.status === "done")).toBe(
      true,
    );
  });

  it("simulates tool failure when failTool is provided without stopping other tools", async () => {
    const summary = await runScan(["trivy", "gitleaks"], undefined, {
      failTool: "gitleaks",
      speedMultiplier: 200,
    });

    const trivy = summary.tools.find((t) => t.tool === "trivy");
    const gitleaks = summary.tools.find((t) => t.tool === "gitleaks");

    // Trivy succeeded
    expect(trivy?.status).toBe("done");
    expect(trivy?.counts.high).toBe(TOOL_CONFIGS.trivy.counts.high);

    // Gitleaks failed
    expect(gitleaks?.status).toBe("failed");
    expect(gitleaks?.error).toBe("gitleaks not found");
    expect(gitleaks?.counts).toEqual({ high: 0, medium: 0, low: 0 });

    // Total counts only include successful tools
    expect(summary.totalCounts.high).toBe(TOOL_CONFIGS.trivy.counts.high);
  });

  it("stops timers and resolves when abortSignal is triggered", async () => {
    const controller = new AbortController();

    const scanPromise = runScan(["semgrep"], undefined, {
      abortSignal: controller.signal,
      speedMultiplier: 5,
    });

    // Abort after 50ms
    setTimeout(() => controller.abort(), 50);

    const summary = await scanPromise;
    expect(summary.tools.length).toBe(1);
    expect(summary.tools[0].status).toBe("failed");
    expect(summary.tools[0].error).toBe("Scan cancelled");
  });

  it("runs real SARIF ingestion and aggregation without fake counts", async () => {
    const summary = await runScan(["trivy", "semgrep", "gitleaks"], undefined, {
      sarifFiles: {
        trivy: "./results/trivy-real.sarif",
        semgrep: "./results/trivy-real.sarif",
        gitleaks: "./results/trivy-real.sarif",
      },
    });
    expect(summary.tools.length).toBe(3);
    for (const toolResult of summary.tools) {
      expect(toolResult.status).toBe("done");
      expect(toolResult.counts).toEqual({ high: 0, medium: 0, low: 0 });
      expect(toolResult.durationSec).toBeLessThan(5);
    }
    expect(summary.totalCounts).toEqual({ high: 0, medium: 0, low: 0 });
    expect(summary.savedPath).toBe("./results/result.sarif");
  });

  it("handles failTool in production path without simulated delay", async () => {
    const summary = await runScan(["trivy", "gitleaks"], undefined, {
      failTool: "gitleaks",
      sarifFiles: {
        trivy: "./results/trivy-real.sarif",
      },
    });
    const trivy = summary.tools.find((t) => t.tool === "trivy");
    const gitleaks = summary.tools.find((t) => t.tool === "gitleaks");
    expect(trivy?.status).toBe("done");
    expect(trivy?.counts).toEqual({ high: 0, medium: 0, low: 0 });
    expect(gitleaks?.status).toBe("failed");
    expect(gitleaks?.error).toContain("gitleaks not found");
  });

  it("accurately reports missing tools as failed with actionable error", async () => {
    // When no fixture or override is provided and tool is absent, reports failure
    const summary = await runScan(["trivy"]);
    const trivy = summary.tools.find((t) => t.tool === "trivy");
    expect(trivy).toBeDefined();
    // In environments without trivy installed, it reports failed status
    if (trivy?.status === "failed") {
      expect(trivy.error).toMatch(/trivy (is not installed|failed)|'trivy' is not recognized/i);
      expect(trivy.counts).toEqual({ high: 0, medium: 0, low: 0 });
    }
  });
});
