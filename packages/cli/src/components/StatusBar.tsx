import React from 'react';
import { Box, Text } from 'ink';

export interface StatusBarProps {
  repo?: string;
  tools?: string;
  lastScan?: string;
}

export function StatusBar({
  repo = './NodeGoat',
  tools = 'trivy, semgrep, gitleaks',
  lastScan = 'none'
}: StatusBarProps) {
  return (
    <Box flexDirection="row" marginY={0}>
      <Text dimColor>repo </Text>
      <Text>{repo}   </Text>
      <Text dimColor>tools </Text>
      <Text>{tools}   </Text>
      <Text dimColor>last scan </Text>
      <Text>{lastScan}</Text>
    </Box>
  );
}
