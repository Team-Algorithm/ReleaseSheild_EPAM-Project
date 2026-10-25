import React from 'react';
import { describe, it, expect } from 'vitest';
import { render } from 'ink-testing-library';
import { HelpScreen } from '../src/screens/HelpScreen.js';
import type { CommandEntry } from '../src/commands/registry.js';

describe('Help Screen (Ink UI)', () => {
  const sampleCommands: CommandEntry[] = [
    {
      name: 'scan',
      description: 'Run a security scan with selected tools',
      usage: '/scan [--tools trivy,semgrep] [--fail <tool>]',
      handler: () => {}
    },
    {
      name: 'results',
      description: 'Show results from the latest security scan',
      usage: '/results',
      handler: () => {}
    },
    {
      name: 'findings',
      description: 'List security findings with optional filters',
      usage: '/findings [--severity high|medium|low] [--tool <tool>]',
      handler: () => {}
    },
    {
      name: 'clear',
      description: 'Clear the terminal output area',
      usage: '/clear',
      handler: () => {}
    },
    {
      name: 'quit',
      description: 'Exit ReleaseShield',
      usage: '/quit',
      handler: () => {}
    }
  ];

  it('renders commands list, descriptions, and prompt history hint', () => {
    const { lastFrame } = render(<HelpScreen commands={sampleCommands} />);
    const frame = lastFrame();

    expect(frame).toContain('Commands');
    expect(frame).toContain('/scan');
    expect(frame).toContain('Run a security scan with selected tools');
    expect(frame).toContain('/results');
    expect(frame).toContain('Show results from the latest security scan');
    expect(frame).toContain('/findings');
    expect(frame).toContain('List security findings with optional filters');
    expect(frame).toContain('/clear');
    expect(frame).toContain('Clear the terminal output area');
    expect(frame).toContain('/quit');
    expect(frame).toContain('Exit ReleaseShield');
    expect(frame).toContain('Type any command at the prompt. Use arrow keys for history.');
  });
});
