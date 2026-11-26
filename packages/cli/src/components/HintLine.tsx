import React from 'react';
import { Box, Text } from 'ink';

export function HintLine() {
  return (
    <Box flexDirection="row" marginTop={1}>
      <Text color="yellow">● </Text>
      <Text bold>Commands: </Text>
      <Text color="cyan">/scan</Text>
      <Text dimColor>  •  </Text>
      <Text color="cyan">/findings</Text>
      <Text dimColor>  •  </Text>
      <Text color="cyan">/results</Text>
      <Text dimColor>  •  </Text>
      <Text color="cyan">/export</Text>
      <Text dimColor>  •  </Text>
      <Text color="cyan">/tools</Text>
      <Text dimColor>  •  </Text>
      <Text color="cyan">/help</Text>
    </Box>
  );
}
