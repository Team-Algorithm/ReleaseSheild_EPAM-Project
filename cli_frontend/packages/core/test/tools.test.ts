import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import {
  getToolRunner,
  TrivyRunner,
  SemgrepRunner,
  GitleaksRunner,
} from "../src/Scanner/tools.js";

describe("Tool Runners Integration Layer", () => {
  const tmpDir = path.join(process.cwd(), ".tmp-test-tools");

  beforeEach(async () => {
    await fs.mkdir(tmpDir, { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("retrieves runner instances for all supported tools", () => {
    const trivy = getToolRunner("trivy");
    const semgrep = getToolRunner("semgrep");
    const gitleaks = getToolRunner("gitleaks");

    expect(trivy).toBeInstanceOf(TrivyRunner);
    expect(semgrep).toBeInstanceOf(SemgrepRunner);
    expect(gitleaks).toBeInstanceOf(GitleaksRunner);

    expect(trivy.name).toBe("trivy");
    expect(semgrep.name).toBe("semgrep");
    expect(gitleaks.name).toBe("gitleaks");
  });

  it("builds proper CLI arguments for Trivy", () => {
    const runner = new TrivyRunner();
    const args = runner.buildArgs("./my-repo", "./out.sarif");
    expect(args).toEqual([
      "fs",
      "--scanners",
      "vuln",
      "--format",
      "sarif",
      "--output",
      "./out.sarif",
      "./my-repo",
    ]);
  });

  it("builds proper CLI arguments for Semgrep", () => {
    const runner = new SemgrepRunner();
    const args = runner.buildArgs("./my-repo", "./out.sarif");
    expect(args).toEqual([
      "scan",
      "--sarif",
      "--output",
      "./out.sarif",
      "./my-repo",
    ]);
  });

  it("builds proper CLI arguments for Gitleaks", () => {
    const runner = new GitleaksRunner();
    const args = runner.buildArgs("./my-repo", "./out.sarif");
    expect(args).toEqual([
      "detect",
      "--source",
      "./my-repo",
      "--report-format",
      "sarif",
      "--report-path",
      "./out.sarif",
    ]);
  });

  it("purges stale SARIF output files prior to executing", async () => {
    const staleFile = path.join(tmpDir, "stale.sarif");
    await fs.writeFile(staleFile, "stale content", "utf-8");

    const runner = new TrivyRunner();
    // Executing against a non-existent executable or target to trigger early failure
    const result = await runner.run({
      targetPath: "./non-existent",
      outputPath: staleFile,
    });

    // Stale file must have been deleted
    const fileExists = await fs
      .access(staleFile)
      .then(() => true)
      .catch(() => false);
    expect(fileExists).toBe(false);
    expect(result.status).toBe("failed");
  });

  it("fails explicitly when tool produces missing or malformed SARIF (never clean scan)", async () => {
    const runner = new GitleaksRunner();
    const targetOutput = path.join(tmpDir, "gitleaks-missing.sarif");

    const result = await runner.run({
      targetPath: "./some-target",
      outputPath: targetOutput,
    });

    expect(result.status).toBe("failed");
    expect(result.error).toBeDefined();
    expect(result.error).not.toBe("");
  });
});
