import React from 'react';
import { Box, Text } from 'ink';

export function HintLine() {
  return (
    <Box justifyContent="space-between" width="100%" marginTop={0}>
      <Text dimColor>/repo  /scan  /tools  /results  /findings  /export  /help</Text>
      <Text dimColor>Ctrl+C to quit</Text>
    </Box>
  );
}
