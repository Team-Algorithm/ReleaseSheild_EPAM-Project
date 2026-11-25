import React from 'react';
import { describe, it, expect } from 'vitest';
import { render } from 'ink-testing-library';
import { ResultsScreen } from '../src/screens/ResultsScreen.js';
import type { ScanSummary } from '@releaseshield/core';

describe('Results Table (Ink UI)', () => {
  const sampleSummary: ScanSummary = {
    tools: [
      {
        tool: 'trivy',
        status: 'done',
        durationSec: 18.2,
        counts: { high: 12, medium: 20, low: 10 }
      },
      {
        tool: 'semgrep',
        status: 'done',
        durationSec: 41.7,
        counts: { high: 11, medium: 15, low: 5 }
      },
      {
        tool: 'gitleaks',
        status: 'done',
        durationSec: 6.9,
        counts: { high: 3, medium: 0, low: 0 }
      }
    ],
    totalCounts: { high: 26, medium: 35, low: 15 },
    totalDurationSec: 41.7,
    savedPath: './results/result.sarif'
  };

  it('renders table columns, tool rows, totals, and saved SARIF path', () => {
    const { lastFrame } = render(<ResultsScreen summary={sampleSummary} columns={80} />);
    const frame = lastFrame();

    // Check tool status lines
    expect(frame).toContain('Trivy');
    expect(frame).toContain('Semgrep');
    expect(frame).toContain('Gitleaks');
    expect(frame).toContain('done');
    expect(frame).toContain('18.2s');
    expect(frame).toContain('41.7s');
    expect(frame).toContain('6.9s');

    // Check table headers
    expect(frame).toContain('Tool');
    expect(frame).toContain('High');
    expect(frame).toContain('Medium');
    expect(frame).toContain('Low');
    expect(frame).toContain('Total');

    // Check tool rows
    expect(frame).toContain('12');
    expect(frame).toContain('20');
    expect(frame).toContain('10');
    expect(frame).toContain('42');

    // Check total row
    expect(frame).toContain('26');
    expect(frame).toContain('35');
    expect(frame).toContain('15');
    expect(frame).toContain('76');
    expect(frame).toContain('total time 42s');

    // Check saved path footer
    expect(frame).toContain('Saved: ./results/result.sarif');
  });

  it('drops Medium and Low columns on narrow terminals (<80 cols)', () => {
    const { lastFrame } = render(<ResultsScreen summary={sampleSummary} columns={60} />);
    const frame = lastFrame();

    // Contains Tool, High, Total
    expect(frame).toContain('Tool');
    expect(frame).toContain('High');
    expect(frame).toContain('Total');

    // Does NOT contain Medium or Low
    expect(frame).not.toContain('Medium');
    expect(frame).not.toContain('Low');
  });

  it('renders failed tool with error message in red/failed status', () => {
    const failedSummary: ScanSummary = {
      tools: [
        {
          tool: 'gitleaks',
          status: 'failed',
          durationSec: 1.0,
          counts: { high: 0, medium: 0, low: 0 },
          error: 'gitleaks not found'
        }
      ],
      totalCounts: { high: 0, medium: 0, low: 0 },
      totalDurationSec: 1.0,
      savedPath: './results/result.sarif'
    };

    const { lastFrame } = render(<ResultsScreen summary={failedSummary} columns={80} />);
    const frame = lastFrame();

    expect(frame).toContain('Gitleaks');
    expect(frame).toContain('failed');
    expect(frame).toContain('gitleaks not found');
  });
});
