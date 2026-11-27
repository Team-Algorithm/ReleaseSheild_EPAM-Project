import React from 'react';
import { Box, Text, useStdout } from 'ink';

const FONT: Record<string, [string, string, string]> = {
  R: ['█▀▀█', '█▄▄▀', '▀  ▀'],
  E: ['█▀▀', '█▀▀', '▀▀▀'],
  L: ['█  ', '█  ', '▀▀▀'],
  A: ['█▀▀█', '█▄▄█', '▀  ▀'],
  S: ['█▀▀', '▀▀█', '▀▀▀'],
  H: ['█  █', '█▀▀█', '▀  ▀'],
  I: ['█', '█', '▀'],
  D: ['█▀▀▄', '█  █', '▀▀▀ '],
  ' ': ['  ', '  ', '  ']
};

function getGlyphRow(text: string, rowIdx: 0 | 1 | 2): string {
  let s = '';
  for (const ch of text) {
    const g = FONT[ch] || ['   ', '   ', '   '];
    s += g[rowIdx] + ' ';
  }
  return s;
}

const SHIELD_R0 = getGlyphRow('RELEASE SHIELD', 0);
const SHIELD_R1 = getGlyphRow('RELEASE SHIELD', 1);
const SHIELD_R2 = getGlyphRow('RELEASE SHIELD', 2);

const AI_R0 = getGlyphRow('AI', 0);
const AI_R1 = getGlyphRow('AI', 1);
const AI_R2 = getGlyphRow('AI', 2);

export function Header() {
  const { stdout } = useStdout();
  const terminalWidth = (stdout as any)?.columns ?? process.stdout?.columns ?? 80;
  const showBanner = terminalWidth >= 70;

  return (
    <Box flexDirection="column" alignItems="center" width="100%" marginY={1}>
      {showBanner ? (
        <Box flexDirection="column" alignItems="center">
          <Box flexDirection="row">
            <Text color="#f8fafc">{SHIELD_R0} </Text>
            <Text color="#38bdf8" bold>{AI_R0}</Text>
          </Box>
          <Box flexDirection="row">
            <Text color="#cbd5e1">{SHIELD_R1} </Text>
            <Text color="#38bdf8" bold>{AI_R1}</Text>
          </Box>
          <Box flexDirection="row">
            <Text color="#64748b">{SHIELD_R2} </Text>
            <Text color="#0284c7">{AI_R2}</Text>
          </Box>
        </Box>
      ) : (
        <Box flexDirection="row">
          <Text bold color="#f8fafc">Release Shield </Text>
          <Text bold color="#38bdf8">AI</Text>
        </Box>
      )}

      {/* Clean Subtitle (No duplicate title text) */}
      <Box marginTop={1}>
        <Text dimColor>AI-Powered Automated DevSecOps Release Gate & Posture Engine</Text>
      </Box>
    </Box>
  );
}
