import React from 'react';
import { describe, it, expect } from 'vitest';
import { render } from 'ink-testing-library';
import { App } from '../../packages/cli/src/App.js';

describe('CLI App Layout & OpenCode aesthetic', () => {
  it('renders Release Shield AI banner, input prompt with accent, commands, and git status', () => {
    process.env.NODE_ENV = 'test';
    process.env.COLUMNS = '80';
    const { lastFrame } = render(<App />);
    const frame = lastFrame() || '';

    // Verify subtitle
    expect(frame).toContain('AI-Powered Automated DevSecOps Release Gate & Posture Engine');
    // Verify prompt container subline
    expect(frame).toContain('Engine · Trivy (SCA) + Semgrep (SAST) + Gitleaks (Secrets)');
    expect(frame).not.toContain('EPAM CoE');
    // Verify right-aligned shortcut key
    expect(frame).toContain('ctrl+c exit');
    // Verify commands list with bullet separators and NO descriptions
    expect(frame).toContain('Commands: /scan');
    expect(frame).toContain('/findings');
    expect(frame).toContain('/results');
    expect(frame).toContain('/export');
    expect(frame).toContain('/tools');
    expect(frame).toContain('/help');
    expect(frame).not.toContain('run security scan');
    expect(frame).not.toContain('view & filter');
    // Verify no version number
    expect(frame).not.toContain('v1.19');
  });
});
