import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs/promises";
import * as fsSync from "node:fs";
import * as path from "node:path";
import { EventEmitter } from "node:events";
import * as toolsModule from "../src/Scanner/tools.js";
import {
  SemgrepRunner,
  getToolRunner,
  checkToolAvailability,
} from "../src/Scanner/tools.js";
import {
  isSemgrepAvailable,
  buildSemgrepArgs,
  runSemgrep,
} from "../src/Scanner/semgrep.js";
import { runScan } from "../src/scan.js";
import {
  readSarifFile,
  countFindings,
  extractFindings,
} from "../src/sarif/index.js";
import type { ToolRunOptions, ToolRunOutput, SarifLog } from "../src/types.js";

const VALID_SEMGREP_SARIF: SarifLog = {
  $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "Semgrep OSS",
          rules: [
            {
              id: "javascript.browser.security.eval-detected",
              name: "EvalDetected",
              defaultConfiguration: { level: "warning" },
              properties: { "security-severity": "7.5" },
            },
          ],
        },
      },
      results: [
        {
          ruleId: "javascript.browser.security.eval-detected",
          level: "error",
          message: { text: "Dangerous eval() detected" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/utils.js" },
                region: { startLine: 15, startColumn: 5 },
              },
            },
          ],
        },
      ],
    },
  ],
};

const EMPTY_SEMGREP_SARIF: SarifLog = {
  $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "Semgrep OSS",
        },
      },
      results: [],
    },
  ],
};

function createMockProcess(exitCode: number, stdout = "", stderr = "", delayMs = 10) {
  const proc = new EventEmitter() as any;
  proc.stdout = new EventEmitter();
  proc.stderr = new EventEmitter();
  proc.kill = vi.fn(() => {
    proc.emit("close", null);
  });

  setTimeout(() => {
    if (stdout) proc.stdout.emit("data", Buffer.from(stdout));
    if (stderr) proc.stderr.emit("data", Buffer.from(stderr));
    proc.emit("close", exitCode);
  }, delayMs);

  return proc;
}

describe("Semgrep Integration & Test Suite", () => {
  const tmpDir = path.resolve("./results/test-semgrep");
  const testOutputPath = path.join(tmpDir, "semgrep.sarif");

  beforeEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(tmpDir, { recursive: true, force: true });
    await fs.mkdir(tmpDir, { recursive: true });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  // 1. A valid SARIF report containing findings
  it("Scenario 1: Processes valid Semgrep SARIF report containing findings", async () => {
    const runner = new SemgrepRunner();
    runner.spawnFn = () => {
      fsSync.writeFileSync(testOutputPath, JSON.stringify(VALID_SEMGREP_SARIF), "utf-8");
      return createMockProcess(1); // Exit 1 with findings
    };

    const output = await runner.run({
      targetPath: "./src",
      outputPath: testOutputPath,
    });

    expect(output.status).toBe("done");
    expect(output.counts.high).toBe(1);
    expect(output.sarifLog?.runs[0].tool.driver.name).toBe("Semgrep OSS");
  });

  // 2. A valid SARIF report containing zero findings
  it("Scenario 2: Handles a valid Semgrep SARIF report containing zero findings", async () => {
    const runner = new SemgrepRunner();
    runner.spawnFn = () => {
      fsSync.writeFileSync(testOutputPath, JSON.stringify(EMPTY_SEMGREP_SARIF), "utf-8");
      return createMockProcess(0);
    };

    const output = await runner.run({
      targetPath: "./src",
      outputPath: testOutputPath,
    });

    expect(output.status).toBe("done");
    expect(output.counts).toEqual({ high: 0, medium: 0, low: 0 });
    expect(output.exitCode).toBe(0);
  });

  // 3. An unavailable executable
  it("Scenario 3: Handles an unavailable executable cleanly without crashing", async () => {
    const runner = new SemgrepRunner();
    runner.spawnFn = () => {
      const proc = new EventEmitter() as any;
      proc.stdout = new EventEmitter();
      proc.stderr = new EventEmitter();
      proc.kill = vi.fn();
      setTimeout(() => {
        proc.emit("error", new Error("spawn semgrep ENOENT"));
        proc.emit("close", 1);
      }, 5);
      return proc;
    };

    const isAvail = await runner.isAvailable();
    expect(isAvail).toBe(false);

    const output = await runner.run({
      targetPath: "./src",
      outputPath: testOutputPath,
    });

    expect(output.status).toBe("failed");
    expect(output.error).toContain("semgrep not found");
  });

  // 4. A scanner execution failure (fatal exit code >= 2)
  it("Scenario 4: Handles a fatal scanner execution failure (exit code 2 or crash)", async () => {
    const runner = new SemgrepRunner();
    runner.spawnFn = () => {
      return createMockProcess(2, "", "fatal configuration error in rules");
    };

    const output = await runner.run({
      targetPath: "./src",
      outputPath: testOutputPath,
    });

    expect(output.status).toBe("failed");
    expect(output.exitCode).toBe(2);
    expect(output.error).toContain("fatal configuration error");
  });

  // 5. Findings-related exit-code behavior (exit code 1 is valid when findings exist)
  it("Scenario 5: Recognizes exit code 1 as a valid findings exit code when SARIF is present", async () => {
    const runner = new SemgrepRunner();
    runner.spawnFn = () => {
      fsSync.writeFileSync(testOutputPath, JSON.stringify(VALID_SEMGREP_SARIF), "utf-8");
      return createMockProcess(1); // Semgrep convention for findings
    };

    const output = await runner.run({
      targetPath: "./src",
      outputPath: testOutputPath,
    });

    expect(output.status).toBe("done");
    expect(output.exitCode).toBe(1);
    expect(output.counts.high).toBe(1);
  });

  // 6. Missing report output
  it("Scenario 6: Fails explicitly when Semgrep exits without producing a report file", async () => {
    const runner = new SemgrepRunner();
    runner.spawnFn = () => {
      return createMockProcess(0);
    };

    const output = await runner.run({
      targetPath: "./src",
      outputPath: testOutputPath,
    });

    expect(output.status).toBe("failed");
    expect(output.error).toContain("without producing a valid SARIF report");
    expect(fsSync.existsSync(testOutputPath)).toBe(false);
  });

  // 7. Malformed JSON
  it("Scenario 7: Fails when Semgrep produces malformed non-JSON output", async () => {
    const runner = new SemgrepRunner();
    runner.spawnFn = () => {
      fsSync.writeFileSync(testOutputPath, "NOT_JSON{{{bad-semgrep-output", "utf-8");
      return createMockProcess(0);
    };

    const output = await runner.run({
      targetPath: "./src",
      outputPath: testOutputPath,
    });

    expect(output.status).toBe("failed");
    expect(output.error).toContain("SARIF");
    expect(fsSync.existsSync(testOutputPath)).toBe(false); // Stale file removed
  });

  // 8. Schema-invalid SARIF
  it("Scenario 8: Rejects schema-invalid SARIF output from Semgrep", async () => {
    const runner = new SemgrepRunner();
    runner.spawnFn = () => {
      fsSync.writeFileSync(testOutputPath, JSON.stringify({ version: "1.0.0" }), "utf-8");
      return createMockProcess(0);
    };

    const output = await runner.run({
      targetPath: "./src",
      outputPath: testOutputPath,
    });

    expect(output.status).toBe("failed");
    expect(output.error).toContain("SARIF");
    expect(fsSync.existsSync(testOutputPath)).toBe(false);
  });

  // 9. Timeout and cleanup behavior
  it("Scenario 9: Enforces timeout and cleans up incomplete reports", async () => {
    const runner = new SemgrepRunner();
    runner.spawnFn = () => {
      return createMockProcess(0, "", "", 10000);
    };

    const output = await runner.run({
      targetPath: "./src",
      outputPath: testOutputPath,
      timeoutMs: 50,
    });

    expect(output.status).toBe("failed");
    expect(output.error).toContain("timed out after 50ms");
    expect(fsSync.existsSync(testOutputPath)).toBe(false);
  });

  // 10. Correct target-path forwarding, including Windows paths
  it("Scenario 10: Forwards target path with Windows backslashes properly", () => {
    const runner = new SemgrepRunner();
    const windowsPath = "D:\\Projects\\TestApp";
    const outPath = "D:\\Projects\\TestApp\\results\\semgrep.sarif";

    const args = runner.buildArgs(windowsPath, outPath);

    expect(args).toContain(windowsPath);
    expect(args).toContain(outPath);
    expect(args).toContain("--sarif");
    expect(args).toContain("--config");
  });

  // 11. Correct merging with Trivy and Gitleaks
  it("Scenario 11: Merges Semgrep SARIF report with Trivy and Gitleaks reports", async () => {
    const mergedFile = path.join(tmpDir, "result.sarif");
    const trivyOut = path.join(tmpDir, "trivy.sarif");
    const gitleaksOut = path.join(tmpDir, "gitleaks.sarif");

    vi.spyOn(toolsModule, "getToolRunner").mockImplementation((toolName) => ({
      name: toolName,
      isAvailable: async () => true,
      buildArgs: () => [],
      run: async (options: ToolRunOptions): Promise<ToolRunOutput> => {
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        if (toolName === "semgrep") {
          await fs.writeFile(options.outputPath, JSON.stringify(VALID_SEMGREP_SARIF), "utf-8");
          return {
            tool: "semgrep",
            status: "done",
            durationSec: 0.6,
            counts: { high: 1, medium: 0, low: 0 },
          };
        }
        const dummyReport = {
          version: "2.1.0",
          runs: [{ tool: { driver: { name: toolName } }, results: [] }],
        };
        await fs.writeFile(options.outputPath, JSON.stringify(dummyReport), "utf-8");
        return {
          tool: toolName,
          status: "done",
          durationSec: 0.3,
          counts: { high: 0, medium: 0, low: 0 },
        };
      },
    } as unknown as toolsModule.ToolRunner));

    const summary = await runScan(["trivy", "gitleaks", "semgrep"], undefined, {
      outputPath: mergedFile,
      sarifFiles: { trivy: trivyOut, gitleaks: gitleaksOut, semgrep: testOutputPath },
    });

    expect(summary.tools.length).toBe(3);
    expect(summary.tools.every((t) => t.status === "done")).toBe(true);
    expect(summary.savedPath).toBe(mergedFile);

    const merged = await readSarifFile(mergedFile);
    expect(merged.runs.length).toBe(3);
    const driverNames = merged.runs.map((r) => r.tool.driver.name);
    expect(driverNames).toContain("Semgrep OSS");
    expect(driverNames).toContain("trivy");
    expect(driverNames).toContain("gitleaks");
  });

  // 12. Failure isolation when Semgrep fails
  it("Scenario 12: Preserves Trivy and Gitleaks results if Semgrep crashes", async () => {
    const mergedFile = path.join(tmpDir, "result.sarif");
    const trivyOut = path.join(tmpDir, "trivy.sarif");

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
            error: "Semgrep process crashed with OOM",
          };
        }
        await fs.mkdir(path.dirname(options.outputPath), { recursive: true });
        const trivyReport = {
          version: "2.1.0",
          runs: [
            {
              tool: { driver: { name: "Trivy" } },
              results: [{ ruleId: "CVE-1", level: "error", message: { text: "Vuln" } }],
            },
          ],
        };
        await fs.writeFile(options.outputPath, JSON.stringify(trivyReport), "utf-8");
        return {
          tool: toolName,
          status: "done",
          durationSec: 0.3,
          counts: { high: 1, medium: 0, low: 0 },
        };
      },
    } as unknown as toolsModule.ToolRunner));

    const summary = await runScan(["trivy", "semgrep"], undefined, {
      outputPath: mergedFile,
      sarifFiles: { trivy: trivyOut, gitleaks: "", semgrep: testOutputPath },
    });

    const semgrepRes = summary.tools.find((t) => t.tool === "semgrep");
    const trivyRes = summary.tools.find((t) => t.tool === "trivy");

    expect(semgrepRes?.status).toBe("failed");
    expect(trivyRes?.status).toBe("done");
    expect(summary.totalCounts.high).toBe(1);
    expect(summary.savedPath).toBe(mergedFile);

    const merged = await readSarifFile(mergedFile);
    expect(merged.runs.length).toBe(1);
    expect(merged.runs[0].tool.driver.name).toBe("Trivy");
  });

  // 13. Correct severity counts and finding extraction
  it("Scenario 13: Normalizes Semgrep OSS tool name and calculates severity counts accurately", () => {
    const counts = countFindings(VALID_SEMGREP_SARIF);
    expect(counts).toEqual({ high: 1, medium: 0, low: 0 });

    const findings = extractFindings(VALID_SEMGREP_SARIF);
    expect(findings.length).toBe(1);
    expect(findings[0].tool).toBe("semgrep");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].rule).toBe("javascript.browser.security.eval-detected");
    expect(findings[0].location).toBe("src/utils.js");
    expect(findings[0].line).toBe(15);
  });

  // 14. Prevention of stale-report reuse
  it("Scenario 14: Deletes pre-existing Semgrep report before scan execution", async () => {
    await fs.writeFile(testOutputPath, "STALE_OLD_REPORT", "utf-8");
    expect(fsSync.existsSync(testOutputPath)).toBe(true);

    const runner = new SemgrepRunner();
    runner.spawnFn = () => {
      return createMockProcess(2, "", "execution error");
    };

    await runner.run({
      targetPath: "./src",
      outputPath: testOutputPath,
    });

    // Stale report MUST have been purged prior to execution
    expect(fsSync.existsSync(testOutputPath)).toBe(false);
  });

  // Wrapper function tests
  describe("Semgrep wrapper helpers (semgrep.ts)", () => {
    it("validates missing targetPath and missing outputPath", async () => {
      const res1 = await runSemgrep({ targetPath: "", outputPath: "./out.sarif" });
      expect(res1.status).toBe("failed");
      expect(res1.error).toContain("target repository path is required");

      const res2 = await runSemgrep({ targetPath: "./src", outputPath: "" });
      expect(res2.status).toBe("failed");
      expect(res2.error).toContain("SARIF output path is required");
    });

    it("buildSemgrepArgs delegates to SemgrepRunner", () => {
      const args = buildSemgrepArgs("./src", "./out.sarif");
      expect(args).toContain("scan");
      expect(args).toContain("./src");
      expect(args).toContain("./out.sarif");
    });

    it("isSemgrepAvailable checks tool runner availability", async () => {
      vi.spyOn(toolsModule, "checkToolAvailability").mockResolvedValue(true);
      const avail = await isSemgrepAvailable();
      expect(avail).toBe(true);
    });
  });
});
