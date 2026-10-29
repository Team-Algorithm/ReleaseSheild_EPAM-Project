import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runNonInteractiveScan } from "../src/nonInteractive.js";
import * as core from "@releaseshield/core";
import type { ScanSummary } from "@releaseshield/core";

describe("runNonInteractiveScan CLI", () => {
  let stdoutChunks: string[] = [];
  let originalStdoutWrite: typeof process.stdout.write;

  beforeEach(() => {
    stdoutChunks = [];
    originalStdoutWrite = process.stdout.write;
    process.stdout.write = vi.fn((chunk: string | Uint8Array) => {
      stdoutChunks.push(chunk.toString());
      return true;
    }) as any;
  });

  afterEach(() => {
    process.stdout.write = originalStdoutWrite;
    vi.restoreAllMocks();
  });

  it("displays human-readable findings breakdown and Saved path when scan produces a valid report", async () => {
    const mockSummary: ScanSummary = {
      tools: [
        {
          tool: "trivy",
          status: "done",
          durationSec: 1.2,
          counts: { high: 1, medium: 2, low: 0 }
        }
      ],
      totalCounts: { high: 1, medium: 2, low: 0 },
      totalDurationSec: 1.2,
      savedPath: "./results/result.sarif"
    };

    const runScanSpy = vi.spyOn(core, "runScan").mockResolvedValue(mockSummary);

    const exitCode = await runNonInteractiveScan({
      repo: "./custom-target",
      tools: ["trivy"],
      json: false
    });

    const output = stdoutChunks.join("");
    expect(exitCode).toBe(0);
    expect(runScanSpy).toHaveBeenCalledWith(["trivy"], undefined, {
      failTool: undefined,
      targetPath: "./custom-target"
    });
    expect(output).toContain("Scan completed for ./custom-target");
    expect(output).toContain("Findings: 3 total (High: 1, Medium: 2, Low: 0)");
    expect(output).toContain("Total time: 1.2s");
    expect(output).toContain("Saved: ./results/result.sarif");
    expect(output).not.toContain("No report saved");
  });

  it("displays zero findings breakdown when scan finds 0 vulnerabilities", async () => {
    const mockSummary: ScanSummary = {
      tools: [
        {
          tool: "gitleaks",
          status: "done",
          durationSec: 0.4,
          counts: { high: 0, medium: 0, low: 0 }
        }
      ],
      totalCounts: { high: 0, medium: 0, low: 0 },
      totalDurationSec: 0.4,
      savedPath: "./results/result.sarif"
    };

    vi.spyOn(core, "runScan").mockResolvedValue(mockSummary);

    const exitCode = await runNonInteractiveScan({
      tools: ["gitleaks"],
      json: false
    });

    const output = stdoutChunks.join("");
    expect(exitCode).toBe(0);
    expect(output).toContain("Scan completed for .");
    expect(output).toContain("Findings: 0 total (High: 0, Medium: 0, Low: 0)");
    expect(output).toContain("Saved: ./results/result.sarif");
  });

  it("displays 'No report saved' when scan fails to produce a valid report", async () => {
    const mockSummary: ScanSummary = {
      tools: [
        {
          tool: "trivy",
          status: "failed",
          durationSec: 0.5,
          counts: { high: 0, medium: 0, low: 0 },
          error: "trivy binary not found"
        }
      ],
      totalCounts: { high: 0, medium: 0, low: 0 },
      totalDurationSec: 0.5,
      savedPath: ""
    };

    vi.spyOn(core, "runScan").mockResolvedValue(mockSummary);

    const exitCode = await runNonInteractiveScan({
      tools: ["trivy"],
      json: false
    });

    const output = stdoutChunks.join("");
    expect(exitCode).toBe(1);
    expect(output).toContain("Findings: 0 total (High: 0, Medium: 0, Low: 0)");
    expect(output).toContain("No report saved");
    expect(output).not.toContain("Saved: ");
  });

  it("outputs valid JSON containing savedPath and totalCounts when json mode is enabled", async () => {
    const mockSummary: ScanSummary = {
      tools: [
        {
          tool: "gitleaks",
          status: "done",
          durationSec: 0.8,
          counts: { high: 2, medium: 1, low: 0 }
        }
      ],
      totalCounts: { high: 2, medium: 1, low: 0 },
      totalDurationSec: 0.8,
      savedPath: "./results/result.sarif"
    };

    vi.spyOn(core, "runScan").mockResolvedValue(mockSummary);

    const exitCode = await runNonInteractiveScan({
      tools: ["gitleaks"],
      json: true
    });

    expect(exitCode).toBe(0);
    const output = stdoutChunks.join("");
    const parsed = JSON.parse(output);
    expect(parsed.savedPath).toBe("./results/result.sarif");
    expect(parsed.totalCounts).toEqual({ high: 2, medium: 1, low: 0 });
    expect(parsed.tools[0].tool).toBe("gitleaks");
  });
});
