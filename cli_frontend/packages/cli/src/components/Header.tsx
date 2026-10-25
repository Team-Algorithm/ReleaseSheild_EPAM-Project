import React, { useState, useEffect } from 'react';
import { Box, Text, useStdout } from 'ink';

const FONT: Record<string, [string, string, string]> = {
  r: ['█▀▀█', '█   ', '▀   '],
  e: ['█▀▀█', '█▀▀▀', '▀▀▀▀'],
  l: ['█ ', '█ ', '▀▀'],
  a: [' ▀▀█', '█▀▀█', '▀▀▀▀'],
  s: ['█▀▀▀', '▀▀▀█', '▀▀▀▀'],
  h: ['█   ', '█▀▀█', '▀  ▀'],
  i: ['█', '█', '▀'],
  d: ['   █', '█▀▀█', '▀▀▀▀']
};

const LOGO_TEXT = 'releaseshield';

interface GlyphColumn {
  col: number;
  r0: string;
  r1: string;
  r2: string;
}

const LOGO_COLUMNS: GlyphColumn[] = [];
for (const ch of LOGO_TEXT) {
  const glyph = FONT[ch] || ['   ', '   ', '   '];
  for (let c = 0; c < glyph[0].length; c++) {
    LOGO_COLUMNS.push({
      col: LOGO_COLUMNS.length,
      r0: glyph[0][c],
      r1: glyph[1][c],
      r2: glyph[2][c]
    });
  }
  LOGO_COLUMNS.push({ col: LOGO_COLUMNS.length, r0: ' ', r1: ' ', r2: ' ' });
}

const TOTAL_COLS = LOGO_COLUMNS.length; // ~58 cols

export function Header() {
  const [wavePos, setWavePos] = useState(0);
  const { stdout } = useStdout();
  const terminalWidth = (stdout as any)?.columns ?? process.stdout?.columns ?? 80;
  const showBanner = terminalWidth >= 62;

  const isNoColor = Boolean(
    typeof process !== 'undefined' &&
      process.env.NO_COLOR !== undefined &&
      process.env.NO_COLOR !== ''
  );

  useEffect(() => {
    const interval = setInterval(() => {
      setWavePos((prev) => (prev + 1) % (TOTAL_COLS + 24));
    }, 60);
    return () => clearInterval(interval);
  }, []);

  const getColColor = (col: number, isMiddle: boolean): string | undefined => {
    if (isNoColor) return undefined;
    const dist = Math.abs(col - wavePos);
    if (dist === 0) return '#ffffff'; // Crest peak
    if (dist <= 2) return '#e0f2fe'; // Bright white-blue glow
    if (dist <= 4) return '#38bdf8'; // Electric cyan
    if (dist <= 7) return '#818cf8'; // Cyber indigo shimmer trail
    if (dist <= 10) return '#475569'; // Edge falloff
    return isMiddle ? '#334155' : '#cbd5e1'; // Dark recessed slit in middle vs bright silver caps
  };

  return (
    <Box flexDirection="column" marginY={0}>
      {/* Animated opencode-style block banner for standard/wide terminals */}
      {showBanner && (
        <Box flexDirection="column" marginBottom={1}>
          <Box flexDirection="row">
            {LOGO_COLUMNS.map((item, idx) => (
              <Text key={`r0-${idx}`} color={getColColor(item.col, false)} bold={Math.abs(item.col - wavePos) <= 2}>
                {item.r0}
              </Text>
            ))}
          </Box>
          <Box flexDirection="row">
            {LOGO_COLUMNS.map((item, idx) => (
              <Text key={`r1-${idx}`} color={getColColor(item.col, true)} bold={Math.abs(item.col - wavePos) <= 2}>
                {item.r1}
              </Text>
            ))}
          </Box>
          <Box flexDirection="row">
            {LOGO_COLUMNS.map((item, idx) => (
              <Text key={`r2-${idx}`} color={getColColor(item.col, false)} bold={Math.abs(item.col - wavePos) <= 2}>
                {item.r2}
              </Text>
            ))}
          </Box>
        </Box>
      )}

      {/* Sub-header title & version */}
      <Box flexDirection="row">
        <Text bold>ReleaseShield AI</Text>
        <Text dimColor={!isNoColor}> v0.1</Text>
      </Box>
      <Text dimColor={!isNoColor}>Scan, merge and triage security findings</Text>
    </Box>
  );
}
