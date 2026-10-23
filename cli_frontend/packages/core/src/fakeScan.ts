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
  const envSpeed = process.env.RELEASESHIELD_FAKE_SPEED ? Number(process.env.RELEASESHIELD_FAKE_SPEED) : undefined;
  const speed = options?.speedMultiplier ?? (envSpeed && !Number.isNaN(envSpeed) ? envSpeed : 10);
  const tickIntervalMs = Math.max(10, Math.round(1000 / speed));

  // If no tools selected, return empty summary immediately
  if (tools.length === 0) {
    return {
      tools: [],
      totalCounts: { high: 0, medium: 0, low: 0 },
      totalDurationSec: 0,
      savedPath: './results/result.sarif'
    };
  }

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
    });
  });

  const toolResults = await Promise.all(toolPromises);

  const totalCounts: SeverityCounts = toolResults.reduce(
    (acc, cur) => ({
      high: acc.high + cur.counts.high,
      medium: acc.medium + cur.counts.medium,
      low: acc.low + cur.counts.low
    }),
    { high: 0, medium: 0, low: 0 }
  );

  const totalDurationSec = toolResults.reduce((max, cur) => Math.max(max, cur.durationSec), 0);

  return {
    tools: toolResults,
    totalCounts,
    totalDurationSec,
    savedPath: './results/result.sarif'
  };
}
