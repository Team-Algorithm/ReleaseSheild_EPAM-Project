import React from 'react';
import { Box, Text, useStdout } from 'ink';

interface DividerProps {
  char?: string;
}

export function Divider({ char = '─' }: DividerProps) {
  const { stdout } = useStdout();
  const width = Math.max(40, (stdout?.columns ?? 100) - 4);
  return (
    <Box marginY={0}>
      <Text dimColor>{char.repeat(width)}</Text>
    </Box>
  );
}
