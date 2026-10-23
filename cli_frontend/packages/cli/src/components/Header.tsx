import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';

const TITLE = 'ReleaseShield AI';

export function Header() {
  const [wavePos, setWavePos] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setWavePos((prev) => (prev + 1) % (TITLE.length + 8));
    }, 120);
    return () => clearInterval(interval);
  }, []);

  return (
    <Box flexDirection="column" marginY={0}>
      <Box flexDirection="row">
        {TITLE.split('').map((char, index) => {
          const dist = Math.abs(index - (wavePos - 2));
          if (dist === 0) {
            return (
              <Text key={index} bold color="white">
                {char}
              </Text>
            );
          }
          if (dist === 1) {
            return (
              <Text key={index} bold color="#d0d0d0">
                {char}
              </Text>
            );
          }
          if (dist === 2) {
            return (
              <Text key={index} color="gray">
                {char}
              </Text>
            );
          }
          return (
            <Text key={index} dimColor>
              {char}
            </Text>
          );
        })}
        <Text dimColor> v0.1</Text>
      </Box>
      <Text dimColor>Scan, merge and triage security findings</Text>
    </Box>
  );
}
