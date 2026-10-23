import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';

export function PromptBox() {
  const [cursorVisible, setCursorVisible] = useState(true);

  useEffect(() => {
    const timer = setInterval(() => {
      setCursorVisible((v) => !v);
    }, 530);
    return () => clearInterval(timer);
  }, []);

  return (
    <Box borderStyle="round" paddingX={1} marginY={0}>
      <Text color="cyan">{'> '}</Text>
      <Text>{cursorVisible ? '█' : ' '}</Text>
    </Box>
  );
}
