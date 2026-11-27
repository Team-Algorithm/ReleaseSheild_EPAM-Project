import path from "node:path";
import { readFile, writeFile } from "node:fs/promises";
import type { NormalizedFinding } from "../Normalization/normalize.js";
import { fingerprintFinding } from "./fingerprint.js";

async function main() {
  const resultsDir = path.resolve("packages/core/results");

  const inputFiles = [
    "normalized-trivy.json",
    "normalized-gitleaks.json",
  ];

  const allFindings: NormalizedFinding[] = [];

  for (const file of inputFiles) {
    const filePath = path.join(resultsDir, file);
    const content = await readFile(filePath, "utf8");
    const findings: NormalizedFinding[] = JSON.parse(content);

    if (!Array.isArray(findings)) {
      throw new Error(`${file} must contain a JSON array`);
    }

    allFindings.push(...findings);
    console.log(`${file}: ${findings.length} findings loaded`);
  }

  if (allFindings.length === 0) {
    throw new Error("No real normalized findings found.");
  }

  const fingerprinted = allFindings.map(fingerprintFinding);

  // Exclude evidence because Gitleaks evidence may contain secrets.
  const safeOutput = fingerprinted.map((finding) => ({
    repoId: finding.repoId,
    scanner: finding.scanner,
    ruleId: finding.ruleId,
    title: finding.title,
    normalizedTitle: finding.normalizedTitle,
    severity: finding.severity,
    filePath: finding.filePath,
    startLine: finding.startLine,
    endLine: finding.endLine,
    startColumn: finding.startColumn,
    endColumn: finding.endColumn,
    codeFingerprint: finding.codeFingerprint,
    issueFingerprint: finding.issueFingerprint,
  }));

  const outputPath = path.join(
    resultsDir,
    "fingerprinted-findings.json"
  );

  await writeFile(
    outputPath,
    JSON.stringify(safeOutput, null, 2),
    "utf8"
  );

  const codeCount = safeOutput.filter(
    (item) => item.codeFingerprint !== null
  ).length;

  console.log("\n========== FINGERPRINTING COMPLETE ==========");
  console.log(`Total findings: ${safeOutput.length}`);
  console.log(`Code fingerprints: ${codeCount}`);
  console.log(`Issue fingerprints: ${safeOutput.length}`);
  console.log(`Output: ${outputPath}`);
  console.log("Ready for deduplication.");
}

main().catch((error) => {
  console.error("Fingerprinting failed:", error.message);
  process.exitCode = 1;
});
