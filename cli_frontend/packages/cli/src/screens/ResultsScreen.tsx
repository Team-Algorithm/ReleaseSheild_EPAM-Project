import React from 'react';
import { Box, Text, useStdout } from 'ink';
import type { ScanSummary } from '@releaseshield/core';

export interface ResultsScreenProps {
  summary: ScanSummary;
  columns?: number;
}

export function ResultsScreen({ summary, columns: propColumns }: ResultsScreenProps) {
  const { stdout } = useStdout();
  const terminalWidth =
    propColumns ??
    (typeof process !== 'undefined' && process.env.COLUMNS
      ? Number(process.env.COLUMNS)
      : undefined) ??
    (stdout as any)?.columns ??
    process.stdout?.columns ??
    80;
  const isNarrow = terminalWidth < 80;

  const isNoColor = Boolean(
    typeof process !== 'undefined' &&
      process.env.NO_COLOR !== undefined &&
      process.env.NO_COLOR !== ''
  );

  const safeRed = isNoColor ? undefined : 'red';
  const safeYellow = isNoColor ? undefined : 'yellow';
  const safeGreen = isNoColor ? undefined : 'green';

  const toolColWidth = isNarrow ? 12 : 11;
  const highColWidth = 6;
  const medColWidth = 8;
  const lowColWidth = 5;
  const totalColWidth = 7;

  return (
    <Box flexDirection="column">
      {/* Tool status lines */}
      <Box flexDirection="column" marginBottom={1}>
        {summary.tools.map((toolResult) => {
          const label =
            toolResult.tool.charAt(0).toUpperCase() + toolResult.tool.slice(1);
          return (
            <Box key={toolResult.tool} flexDirection="row">
              <Text>{label.padEnd(toolColWidth)}</Text>
              {toolResult.status === 'done' ? (
                <>
                  <Text color={safeGreen}>{'done'.padEnd(9)}</Text>
                  <Text>
                    {toolResult.durationSec.toFixed(1).padStart(5)}s
                  </Text>
                </>
              ) : (
                <>
                  <Text color={safeRed}>{'failed'.padEnd(9)}</Text>
                  <Text color={safeRed}>
                    {toolResult.error ?? 'unknown error'}
                  </Text>
                </>
              )}
            </Box>
          );
        })}
      </Box>

      {/* Results Table */}
      <Box flexDirection="column">
        {/* Table Header */}
        {isNarrow ? (
          <Box flexDirection="row">
            <Text>{'Tool'.padEnd(toolColWidth)}</Text>
            <Text color={safeRed}>{'High'.padStart(highColWidth)}</Text>
            <Text>{'Total'.padStart(totalColWidth)}</Text>
          </Box>
        ) : (
          <Box flexDirection="row">
            <Text>{'Tool'.padEnd(toolColWidth)}</Text>
            <Text color={safeRed}>{'High'.padStart(highColWidth)}</Text>
            <Text color={safeYellow}>{'Medium'.padStart(medColWidth)}</Text>
            <Text>{'Low'.padStart(lowColWidth)}</Text>
            <Text>{'Total'.padStart(totalColWidth)}</Text>
          </Box>
        )}

        {/* Tool rows (for successful tools) */}
        {summary.tools
          .filter((t) => t.status === 'done')
          .map((toolResult) => {
            const label =
              toolResult.tool.charAt(0).toUpperCase() +
              toolResult.tool.slice(1);
            const total =
              toolResult.counts.high +
              toolResult.counts.medium +
              toolResult.counts.low;
            return isNarrow ? (
              <Box key={toolResult.tool} flexDirection="row">
                <Text>{label.padEnd(toolColWidth)}</Text>
                <Text color={safeRed}>
                  {String(toolResult.counts.high).padStart(highColWidth)}
                </Text>
                <Text>{String(total).padStart(totalColWidth)}</Text>
              </Box>
            ) : (
              <Box key={toolResult.tool} flexDirection="row">
                <Text>{label.padEnd(toolColWidth)}</Text>
                <Text color={safeRed}>
                  {String(toolResult.counts.high).padStart(highColWidth)}
                </Text>
                <Text color={safeYellow}>
                  {String(toolResult.counts.medium).padStart(medColWidth)}
                </Text>
                <Text>
                  {String(toolResult.counts.low).padStart(lowColWidth)}
                </Text>
                <Text>{String(total).padStart(totalColWidth)}</Text>
              </Box>
            );
          })}

        {/* Total row */}
        {(() => {
          const grandTotal =
            summary.totalCounts.high +
            summary.totalCounts.medium +
            summary.totalCounts.low;
          return isNarrow ? (
            <Box flexDirection="row">
              <Text bold>{'Total'.padEnd(toolColWidth)}</Text>
              <Text bold color={safeRed}>
                {String(summary.totalCounts.high).padStart(highColWidth)}
              </Text>
              <Text bold>{String(grandTotal).padStart(totalColWidth)}</Text>
              <Text>   total time {Math.round(summary.totalDurationSec)}s</Text>
            </Box>
          ) : (
            <Box flexDirection="row">
              <Text bold>{'Total'.padEnd(toolColWidth)}</Text>
              <Text bold color={safeRed}>
                {String(summary.totalCounts.high).padStart(highColWidth)}
              </Text>
              <Text bold color={safeYellow}>
                {String(summary.totalCounts.medium).padStart(medColWidth)}
              </Text>
              <Text bold>
                {String(summary.totalCounts.low).padStart(lowColWidth)}
              </Text>
              <Text bold>{String(grandTotal).padStart(totalColWidth)}</Text>
              <Text>   total time {Math.round(summary.totalDurationSec)}s</Text>
            </Box>
          );
        })()}
      </Box>

      {/* Saved SARIF footer */}
      <Box marginTop={1}>
        <Text dimColor={!isNoColor}>Saved: {summary.savedPath}</Text>
      </Box>
    </Box>
  );
}
