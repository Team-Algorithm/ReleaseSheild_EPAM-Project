import React from 'react';
import { Box } from 'ink';

export interface MainAreaProps {
  lastCommandOutput?: React.ReactNode;
}

export function MainArea({ lastCommandOutput }: MainAreaProps) {
  return (
    <Box flexDirection="column" marginY={1}>
      {lastCommandOutput ?? null}
    </Box>
  );
}
