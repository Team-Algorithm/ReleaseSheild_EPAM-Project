import { runScan } from "./scan.js";
import {
  validateSarif,
  parseSarif,
  countFindings,
  extractFindings,
  mergeSarif,
} from "./sarif/index.js";
import { getToolRunner } from "./Scanner/tools.js";
import type { SarifLog } from "./types.js";

async function main() {
  console.log("--- Verifying SARIF Ingestion Layer ---");
  const sampleSarif: SarifLog = {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "semgrep",
            rules: [
              {
                id: "sec.sql-injection",
                properties: { "security-severity": "8.5" },
              },
            ],
          },
        },
        results: [
          {
            ruleId: "sec.sql-injection",
            level: "error",
            message: { text: "Potential SQL injection vulnerability" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "src/db.ts" },
                  region: { startLine: 42 },
                },
              },
            ],
          },
        ],
      },
    ],
  };

  const isValid = validateSarif(sampleSarif);
  console.log(`SARIF Validation check: ${isValid ? "PASSED" : "FAILED"}`);

  const counts = countFindings(sampleSarif);
  console.log("Counted findings by severity:", counts);

  const extracted = extractFindings(sampleSarif);
  console.log(
    `Extracted ${extracted.length} normalized finding(s):`,
    extracted[0],
  );

  const merged = mergeSarif([sampleSarif]);
  console.log(`Merged SARIF runs count: ${merged.runs.length}`);

  console.log("\n--- Verifying Tool Runners Interface ---");
  for (const tool of ["trivy", "semgrep", "gitleaks"] as const) {
    const runner = getToolRunner(tool);
    console.log(
      `Tool Runner [${runner.name}]: command args preview -> ${runner.buildArgs(".", "./results/test.sarif").join(" ")}`,
    );
  }

  console.log("\n--- Verifying Normal Scan Execution ---");
  const summary = await runScan(["trivy", "semgrep", "gitleaks"]);
  console.log("Production scan completed successfully.");
  console.log(
    "Reported tool results:",
    summary.tools.map((t) => `${t.tool}: ${t.status}`),
  );
  console.log("Total counts (clean zero findings):", summary.totalCounts);
}

main().catch(console.error);
