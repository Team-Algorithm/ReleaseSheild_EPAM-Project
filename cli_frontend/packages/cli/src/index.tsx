#!/usr/bin/env node
import React from 'react';
import { parseCliArgs, runNonInteractiveScan } from './nonInteractive.js';

// Parse command-line arguments
const cliParsed = parseCliArgs(process.argv);

if (cliParsed.isHelp) {
  process.stdout.write(`
ReleaseShield AI - Security scanning, triage and SARIF merging CLI

Usage:
  Interactive terminal:
    releaseshield

  Non-interactive scan:
    releaseshield scan <repo-path> [flags]

Flags:
  --tools <all|trivy,semgrep,gitleaks>   Specify tools to run (default: all)
  --json                                 Output results as JSON
  --fail <tool>                          Simulate a tool failure
  --help, -h                             Show this help message
\n`);
  process.exit(0);
}

if (cliParsed.isScanCommand) {
  // Non-interactive scan mode: completely skips Ink
  runNonInteractiveScan(cliParsed.args)
    .then((exitCode) => {
      process.exit(exitCode);
    })
    .catch((err) => {
      process.stderr.write(`Scan error: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(1);
    });
} else {
  // Interactive mode: requires interactive TTY stdin
  if (!process.stdin.isTTY) {
    process.stderr.write(
      'ReleaseShield AI: The interactive terminal requires an interactive TTY.\n' +
      'Run in an interactive terminal or use non-interactive options:\n' +
      '  releaseshield scan ./repo --tools all --json\n'
    );
    process.exit(1);
  }

  // Clean SIGINT handler
  process.on('SIGINT', () => {
    process.exit(0);
  });

  // Launch interactive Ink terminal
  import('ink').then(async ({ render }) => {
    const { App } = await import('./App.js');
    render(React.createElement(App));
  });
}
