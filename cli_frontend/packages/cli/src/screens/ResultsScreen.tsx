import React from 'react';
import { Box, Text } from 'ink';
import type { ScanSummary } from '@releaseshield/core';

export interface ResultsScreenProps {
  summary: ScanSummary;
}

export function ResultsScreen({ summary }: ResultsScreenProps) {
  const toolColWidth = 11;
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
                  <Text color="green">{'done'.padEnd(9)}</Text>
                  <Text>
                    {toolResult.durationSec.toFixed(1).padStart(5)}s
                  </Text>
                </>
              ) : (
                <>
                  <Text color="red">{'failed'.padEnd(9)}</Text>
                  <Text color="red">
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
        <Box flexDirection="row">
          <Text>{'Tool'.padEnd(toolColWidth)}</Text>
          <Text color="red">{'High'.padStart(highColWidth)}</Text>
          <Text color="yellow">{'Medium'.padStart(medColWidth)}</Text>
          <Text>{'Low'.padStart(lowColWidth)}</Text>
          <Text>{'Total'.padStart(totalColWidth)}</Text>
        </Box>

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
            return (
              <Box key={toolResult.tool} flexDirection="row">
                <Text>{label.padEnd(toolColWidth)}</Text>
                <Text color="red">
                  {String(toolResult.counts.high).padStart(highColWidth)}
                </Text>
                <Text color="yellow">
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
          return (
            <Box flexDirection="row">
              <Text bold>{'Total'.padEnd(toolColWidth)}</Text>
              <Text bold color="red">
                {String(summary.totalCounts.high).padStart(highColWidth)}
              </Text>
              <Text bold color="yellow">
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
        <Text dimColor>Saved: {summary.savedPath}</Text>
      </Box>
    </Box>
  );
}
