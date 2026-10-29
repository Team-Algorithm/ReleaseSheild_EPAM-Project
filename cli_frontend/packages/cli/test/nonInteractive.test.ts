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

  it("displays Saved path when scan produces a valid report", async () => {
    const mockSummary: ScanSummary = {
      tools: [
        {
          tool: "trivy",
          status: "done",
          durationSec: 1.2,
          counts: { high: 1, medium: 0, low: 0 }
        }
      ],
      totalCounts: { high: 1, medium: 0, low: 0 },
      totalDurationSec: 1.2,
      savedPath: "./results/result.sarif"
    };

    vi.spyOn(core, "runScan").mockResolvedValue(mockSummary);

    const exitCode = await runNonInteractiveScan({
      tools: ["trivy"],
      json: false
    });

    const output = stdoutChunks.join("");
    expect(exitCode).toBe(0);
    expect(output).toContain("Saved: ./results/result.sarif");
    expect(output).not.toContain("No report saved");
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
    expect(output).toContain("No report saved");
    expect(output).not.toContain("Saved: ");
  });

  it("outputs valid JSON containing savedPath when json mode is enabled", async () => {
    const mockSummary: ScanSummary = {
      tools: [
        {
          tool: "gitleaks",
          status: "done",
          durationSec: 0.8,
          counts: { high: 2, medium: 0, low: 0 }
        }
      ],
      totalCounts: { high: 2, medium: 0, low: 0 },
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
    expect(parsed.tools[0].tool).toBe("gitleaks");
  });
});

