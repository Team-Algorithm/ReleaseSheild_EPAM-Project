import path from 'node:path';
import * as fs from 'node:fs/promises';
import {
  getToolRunner
} from './Scanner/tools.js';

import {
  readSarifFile,
  mergeSarif,
  writeSarifFile,
  buildSummary,
} from './sarif/index.js';

import type {
  ToolName,
  ToolResult,
  SeverityCounts,
  ScanSummary,
  ScanOptions,
  ScanUpdateCallback
} from './types.js';

declare const process: {
  env: Record<string, string | undefined>;
};

export const TOOL_CONFIGS: Record<ToolName, { durationSec: number; counts: SeverityCounts }> = {
  trivy: {
    durationSec: 18.2,
    counts: { high: 12, medium: 20, low: 10 }
  },
  semgrep: {
    durationSec: 41.7,
    counts: { high: 11, medium: 15, low: 5 }
  },
  gitleaks: {
    durationSec: 6.9,
    counts: { high: 3, medium: 0, low: 0 }
  }
};

export async function runScan(
  tools: ToolName[],
  onUpdate?: ScanUpdateCallback,
  options?: ScanOptions
): Promise<ScanSummary> {
  // If no tools selected, return empty summary immediately with empty savedPath
  if (tools.length === 0) {
    return {
      tools: [],
      totalCounts: { high: 0, medium: 0, low: 0 },
      totalDurationSec: 0,
      savedPath: ''
    };
  }

  const envSpeed = process.env.RELEASESHIELD_FAKE_SPEED ? Number(process.env.RELEASESHIELD_FAKE_SPEED) : undefined;
  const isSimulation = options?.speedMultiplier !== undefined || (envSpeed !== undefined && !Number.isNaN(envSpeed));

  // Normal production scan path: no fake finding counts, no artificial delays, no fabricated durations
  if (!isSimulation) {
    const targetPath = path.resolve(options?.targetPath ?? '.');
    const canonicalSavedPath = options?.outputPath ?? './results/result.sarif';
    const finalOutputPath = path.resolve(canonicalSavedPath);

    // Prevent an old report from being mistaken for the current scan.
    await fs.rm(finalOutputPath, { force: true });

    const results = await Promise.all(
      tools.map(async (tool): Promise<ToolResult> => {
        const startTime = Date.now();
        const outputPath = path.resolve(
          options?.sarifFiles?.[tool] ?? `./results/${tool}.sarif`
        );

        onUpdate?.({
          tool,
          status: 'running',
          elapsedSec: 0
        });

        if (options?.abortSignal?.aborted) {
          const result: ToolResult = {
            tool,
            status: 'failed',
            durationSec: 0,
            counts: { high: 0, medium: 0, low: 0 },
            error: 'Scan cancelled'
          };

          onUpdate?.({
            tool,
            status: 'failed',
            elapsedSec: 0,
            error: result.error,
            counts: result.counts
          });

          return result;
        }

        if (options?.failTool === tool) {
          const result: ToolResult = {
            tool,
            status: 'failed',
            durationSec: 0,
            counts: { high: 0, medium: 0, low: 0 },
            error: `${tool} not found (simulated failure)`
          };

          onUpdate?.({
            tool,
            status: 'failed',
            elapsedSec: 0,
            error: result.error,
            counts: result.counts
          });

          return result;
        }

        try {
          // Remove a previous report so it cannot be reused accidentally.
          await fs.rm(outputPath, { force: true });

          const output = await getToolRunner(tool).run({
            targetPath,
            outputPath,
            abortSignal: options?.abortSignal
          });

          const durationSec = Number(
            ((Date.now() - startTime) / 1000).toFixed(1)
          );

          const result: ToolResult = {
            tool,
            status: output.status,
            durationSec,
            counts: output.counts,
            ...(output.error ? { error: output.error } : {})
          };

          onUpdate?.({
            tool,
            status: result.status,
            elapsedSec: durationSec,
            ...(result.error ? { error: result.error } : {}),
            counts: result.counts
          });

          return result;
        } catch (error) {
          const durationSec = Number(
            ((Date.now() - startTime) / 1000).toFixed(1)
          );
          const message =
            error instanceof Error ? error.message : String(error);

          const result: ToolResult = {
            tool,
            status: 'failed',
            durationSec,
            counts: { high: 0, medium: 0, low: 0 },
            error: message
          };

          onUpdate?.({
            tool,
            status: 'failed',
            elapsedSec: durationSec,
            error: message,
            counts: result.counts
          });

          return result;
        }
      })
    );

    // Collect and validate the actual SARIF reports produced by successful scanners.
    const sarifLogs = [];

    for (const result of results) {
      if (result.status === 'failed') {
        continue;
      }

      const reportPath = path.resolve(
        options?.sarifFiles?.[result.tool] ??
          `./results/${result.tool}.sarif`
      );

      try {
        const sarifLog = await readSarifFile(reportPath);
        sarifLogs.push(sarifLog);
      } catch (err) {
        const failedResult = results.find(
          (item) => item.tool === result.tool
        );

        if (failedResult) {
          failedResult.status = 'failed';
          failedResult.error = `Scanner did not produce a valid SARIF report: ${err instanceof Error ? err.message : String(err)}`;
          failedResult.counts = { high: 0, medium: 0, low: 0 };
        }
      }
    }

    let savedPath = '';

    if (sarifLogs.length > 0) {
      try {
        const merged = mergeSarif(sarifLogs);
        await writeSarifFile(finalOutputPath, merged);
        savedPath = canonicalSavedPath;
      } catch (mergeError) {
        // If merging or writing fails, report error clearly and do not represent overall scan as fully successful
        savedPath = '';
        for (const res of results) {
          if (res.status === 'done') {
            res.status = 'failed';
            res.error = `Failed to merge or save SARIF: ${mergeError instanceof Error ? mergeError.message : String(mergeError)}`;
          }
        }
      }
    }

    return buildSummary(results, savedPath);
  }

  // Preserved test / mock simulation path (used by automated tests with speedMultiplier)
  const speed = options?.speedMultiplier ?? (envSpeed && !Number.isNaN(envSpeed) ? envSpeed : 10);
  const tickIntervalMs = Math.max(10, Math.round(1000 / speed));

  // Notify initial state: all tools start running
  for (const tool of tools) {
    onUpdate?.({
      tool,
      status: 'running',
      elapsedSec: 0
    });
  }

  // Run each tool in parallel
  const toolPromises = tools.map((tool) => {
    return new Promise<ToolResult>((resolve) => {
      const config = TOOL_CONFIGS[tool];
      const targetDuration = config.durationSec;
      const willFail = options?.failTool === tool;
      let elapsedSec = 0;

      const timer = setInterval(() => {
        if (options?.abortSignal?.aborted) {
          clearInterval(timer);
          return;
        }
        // If this tool is configured to fail
        if (willFail) {
          clearInterval(timer);
          const failDuration = Math.min(1.0, targetDuration);
          const failResult: ToolResult = {
            tool,
            status: 'failed',
            durationSec: failDuration,
            counts: { high: 0, medium: 0, low: 0 },
            error: `${tool} not found`
          };
          onUpdate?.({
            tool,
            status: 'failed',
            elapsedSec: failDuration,
            error: failResult.error,
            counts: failResult.counts
          });
          resolve(failResult);
          return;
        }

        // Increment simulated time by 1.0 second
        elapsedSec = Number((elapsedSec + 1.0).toFixed(1));

        if (elapsedSec >= targetDuration) {
          clearInterval(timer);
          const finalResult: ToolResult = {
            tool,
            status: 'done',
            durationSec: targetDuration,
            counts: config.counts
          };
          onUpdate?.({
            tool,
            status: 'done',
            elapsedSec: targetDuration,
            counts: config.counts
          });
          resolve(finalResult);
        } else {
          onUpdate?.({
            tool,
            status: 'running',
            elapsedSec
          });
        }
      }, tickIntervalMs);

      if (options?.abortSignal) {
        if (options.abortSignal.aborted) {
          clearInterval(timer);
          resolve({
            tool,
            status: 'failed',
            durationSec: 0,
            counts: { high: 0, medium: 0, low: 0 },
            error: 'Scan cancelled'
          });
          return;
        }

        options.abortSignal.addEventListener('abort', () => {
          clearInterval(timer);
          resolve({
            tool,
            status: 'failed',
            durationSec: elapsedSec,
            counts: { high: 0, medium: 0, low: 0 },
            error: 'Scan cancelled'
          });
        });
      }
    });
  });

  const toolResults = await Promise.all(toolPromises);
  const anyDone = toolResults.some((t) => t.status === 'done');
  const simSavedPath = anyDone ? (options?.outputPath ?? './results/result.sarif') : '';

  return buildSummary(toolResults, simSavedPath);
}
