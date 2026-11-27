import React from 'react';
import { Box, Text } from 'ink';

export interface StatusBarProps {
  repo?: string;
  branch?: string;
}

export function StatusBar({
  repo = '.',
  branch = 'main'
}: StatusBarProps) {
  return (
    <Box flexDirection="row" justifyContent="space-between" width="100%" marginTop={1}>
      <Text dimColor>{repo}:{branch}</Text>
    </Box>
  );
}
