import React from 'react';
import { Box, Text } from 'ink';
import type { CommandEntry } from '../commands/registry.js';

export interface HelpScreenProps {
  commands: CommandEntry[];
}

export function HelpScreen({ commands }: HelpScreenProps) {
  const maxNameLen = Math.max(...commands.map((c) => c.name.length), 8);

  return (
    <Box flexDirection="column" marginY={0}>
      <Text bold color="cyan">
        Commands
      </Text>
      <Box flexDirection="column" marginTop={1}>
        {commands.map((cmd) => (
          <Box key={cmd.name} flexDirection="row">
            <Text bold color="white">
              {(`/${cmd.name}`).padEnd(maxNameLen + 4)}
            </Text>
            <Text>{cmd.description}</Text>
          </Box>
        ))}
      </Box>
      <Box marginTop={1}>
        <Text dimColor>Type any command at the prompt. Use arrow keys for history.</Text>
      </Box>
    </Box>
  );
}
