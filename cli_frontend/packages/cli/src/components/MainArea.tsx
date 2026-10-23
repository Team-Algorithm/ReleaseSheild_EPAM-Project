import React from 'react';
import { Box, Text } from 'ink';

export interface MainAreaProps {
  lastCommandOutput?: React.ReactNode;
}

export function MainArea({ lastCommandOutput }: MainAreaProps) {
  if (lastCommandOutput) {
    return (
      <Box flexDirection="column" marginY={1}>
        {lastCommandOutput}
      </Box>
    );
  }

  const toolColWidth = 14;
  const numColWidth = 9;
  const dividerWidth = toolColWidth + numColWidth * 4;

  return (
    <Box flexDirection="column" marginY={1}>
      {/* Tool status lines */}
      <Box flexDirection="column" marginBottom={1}>
        <Box flexDirection="row">
          <Text>{'Trivy'.padEnd(toolColWidth)}</Text>
          <Text color="green">{'done'.padEnd(12)}</Text>
          <Text>18.2s</Text>
        </Box>
        <Box flexDirection="row">
          <Text>{'Semgrep'.padEnd(toolColWidth)}</Text>
          <Text color="green">{'done'.padEnd(12)}</Text>
          <Text>41.7s</Text>
        </Box>
        <Box flexDirection="row">
          <Text>{'Gitleaks'.padEnd(toolColWidth)}</Text>
          <Text color="green">{'done'.padEnd(12)}</Text>
          <Text> 6.9s</Text>
        </Box>
      </Box>

      {/* Results Table */}
      <Box flexDirection="column">
        {/* Table Header */}
        <Box flexDirection="row">
          <Text bold>{'Tool'.padEnd(toolColWidth)}</Text>
          <Text bold color="red">{'High'.padStart(numColWidth)}</Text>
          <Text bold color="yellow">{'Medium'.padStart(numColWidth)}</Text>
          <Text bold>{'Low'.padStart(numColWidth)}</Text>
          <Text bold>{'Total'.padStart(numColWidth)}</Text>
        </Box>

        {/* Rows */}
        <Box flexDirection="row">
          <Text>{'Trivy'.padEnd(toolColWidth)}</Text>
          <Text color="red">{'12'.padStart(numColWidth)}</Text>
          <Text color="yellow">{'20'.padStart(numColWidth)}</Text>
          <Text>{'10'.padStart(numColWidth)}</Text>
          <Text>{'42'.padStart(numColWidth)}</Text>
        </Box>

        <Box flexDirection="row">
          <Text>{'Semgrep'.padEnd(toolColWidth)}</Text>
          <Text color="red">{'11'.padStart(numColWidth)}</Text>
          <Text color="yellow">{'15'.padStart(numColWidth)}</Text>
          <Text>{'5'.padStart(numColWidth)}</Text>
          <Text>{'31'.padStart(numColWidth)}</Text>
        </Box>

        <Box flexDirection="row">
          <Text>{'Gitleaks'.padEnd(toolColWidth)}</Text>
          <Text color="red">{'3'.padStart(numColWidth)}</Text>
          <Text color="yellow">{'0'.padStart(numColWidth)}</Text>
          <Text>{'0'.padStart(numColWidth)}</Text>
          <Text>{'3'.padStart(numColWidth)}</Text>
        </Box>

        {/* Table Divider */}
        <Box marginY={0}>
          <Text dimColor>{'─'.repeat(dividerWidth)}</Text>
        </Box>

        {/* Total Row */}
        <Box flexDirection="row">
          <Text bold>{'Total'.padEnd(toolColWidth)}</Text>
          <Text bold color="red">{'26'.padStart(numColWidth)}</Text>
          <Text bold color="yellow">{'35'.padStart(numColWidth)}</Text>
          <Text bold>{'15'.padStart(numColWidth)}</Text>
          <Text bold>{'76'.padStart(numColWidth)}</Text>
        </Box>
      </Box>

      {/* Summary footer */}
      <Box flexDirection="column" marginTop={1}>
        <Text>Total time: 41.7s</Text>
        <Box marginTop={1}>
          <Text dimColor>Saved: ./results/result.sarif</Text>
        </Box>
      </Box>
    </Box>
  );
}
