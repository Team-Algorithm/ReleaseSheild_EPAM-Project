import { runScan } from './fakeScan.js';
import { FAKE_FINDINGS } from './findings.js';

async function main() {
  console.log(`Loaded ${FAKE_FINDINGS.length} fake findings.`);
  console.log('--- Starting Normal Scan (trivy, semgrep, gitleaks) ---');
  const startTime = Date.now();

  const summary = await runScan(
    ['trivy', 'semgrep', 'gitleaks'],
    (update) => {
      console.log(`[UPDATE] ${update.tool.padEnd(8)} -> status: ${update.status.padEnd(7)} | elapsed: ${update.elapsedSec.toFixed(1)}s`);
    },
    { speedMultiplier: 50 } // Run at 50x speed for quick verification
  );

  const realWallTimeSec = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log('--- Scan Completed ---');
  console.log(`Reported Total Duration: ${summary.totalDurationSec}s (slowest tool)`);
  console.log(`Real Wall-Clock Time: ${realWallTimeSec}s`);
  console.log('Total Counts:', summary.totalCounts);
  console.log('Tool Results:', summary.tools);

  console.log('\n--- Testing Failure Mode with failTool: gitleaks ---');
  const failSummary = await runScan(
    ['trivy', 'gitleaks'],
    (update) => {
      if (update.status === 'failed' || update.status === 'done') {
        console.log(`[FAIL-TEST] ${update.tool}: ${update.status} (error: ${update.error ?? 'none'})`);
      }
    },
    { speedMultiplier: 50, failTool: 'gitleaks' }
  );
  console.log('Fail test summary tools:', failSummary.tools.map(t => `${t.tool}: ${t.status} (${t.error ?? 'ok'})`));
}

main().catch(console.error);
