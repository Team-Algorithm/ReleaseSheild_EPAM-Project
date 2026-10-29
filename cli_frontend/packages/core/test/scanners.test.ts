import { describe, it, expect } from "vitest";
import * as path from "path";
import {
  isTrivyAvailable,
  buildTrivyArgs,
  runTrivy,
} from "../src/Scanner/trivy.js";
import {
  isSemgrepAvailable,
  buildSemgrepArgs,
  runSemgrep,
} from "../src/Scanner/semgrep.js";
import {
  isGitleaksAvailable,
  buildGitleaksArgs,
  runGitleaks,
} from "../src/Scanner/gitleaks.js";
import { resolveExecutable, getToolRunner } from "../src/tools.js";
import { readSarifFile, extractFindings, countFindings } from "../src/sarif.js";

describe("Security Scanners Integration & Wrappers", () => {
  it("exports runner functions and builds arguments for Semgrep", () => {
    const args = buildSemgrepArgs("./target", "./out.sarif");
    expect(args).toEqual(["scan", "--sarif", "--output", "./out.sarif", "./target"]);
  });

  it("exports runner functions and builds arguments for Gitleaks", () => {
    const args = buildGitleaksArgs("./target", "./out.sarif");
    expect(args).toEqual([
      "detect",
      "--source",
      "./target",
      "--report-format",
      "sarif",
      "--report-path",
      "./out.sarif",
    ]);
  });

  it("exports runner functions and builds arguments for Trivy", () => {
    const args = buildTrivyArgs("./target", "./out.sarif");
    expect(args).toEqual([
      "fs",
      "--format",
      "sarif",
      "--output",
      "./out.sarif",
      "./target",
    ]);
  });

  it("validates required options for runTrivy, runSemgrep, and runGitleaks", async () => {
    const trivyNoTarget = await runTrivy({ targetPath: "", outputPath: "./out.sarif" });
    expect(trivyNoTarget.status).toBe("failed");
    expect(trivyNoTarget.error).toContain("target repository path is required");

    const semgrepNoOutput = await runSemgrep({ targetPath: "./target", outputPath: "" });
    expect(semgrepNoOutput.status).toBe("failed");
    expect(semgrepNoOutput.error).toContain("SARIF output path is required");

    const gitleaksNoTarget = await runGitleaks({ targetPath: "   ", outputPath: "./out.sarif" });
    expect(gitleaksNoTarget.status).toBe("failed");
    expect(gitleaksNoTarget.error).toContain("target repository path is required");
  });

  it("checks availability accurately without throwing", async () => {
    const [trivy, semgrep, gitleaks] = await Promise.all([
      isTrivyAvailable(),
      isSemgrepAvailable(),
      isGitleaksAvailable(),
    ]);

    expect(typeof trivy).toBe("boolean");
    expect(typeof semgrep).toBe("boolean");
    expect(typeof gitleaks).toBe("boolean");

    // In this verified Windows environment, Semgrep and Gitleaks are installed
    expect(semgrep).toBe(true);
    expect(gitleaks).toBe(true);
    // Trivy is not installed
    expect(trivy).toBe(false);
  });

  it("resolveExecutable finds system binaries and respects environment overrides", () => {
    // Should resolve node or git if present on PATH
    const nodeBin = resolveExecutable("node");
    expect(nodeBin).not.toBeNull();

    // Missing tool should resolve to null
    const nonexistent = resolveExecutable("non_existent_scanner_12345");
    expect(nonexistent).toBeNull();

    // Respects TRIVY_PATH if pointing to existing file
    if (nodeBin) {
      process.env.TRIVY_PATH = nodeBin;
      expect(resolveExecutable("trivy")).toBe(nodeBin);
      delete process.env.TRIVY_PATH;
    }

    // Resolves gitleaks and semgrep via known paths or PATH
    expect(resolveExecutable("gitleaks")).not.toBeNull();
    expect(resolveExecutable("semgrep")).not.toBeNull();
  });

  it("parses real Trivy SARIF report fixture and extracts findings into model", async () => {
    const fixturePath = path.resolve("./results/trivy-manual.sarif");
    const sarif = await readSarifFile(fixturePath);
    expect(sarif.version).toBe("2.1.0");

    const counts = countFindings(sarif);
    expect(counts.high + counts.medium + counts.low).toBeGreaterThan(0);

    const findings = extractFindings(sarif);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].tool).toBe("trivy");
    expect(findings[0].rule).toBeDefined();
    expect(findings[0].severity).toMatch(/high|medium|low/);
    expect(findings[0].message).toBeDefined();
  });
});
