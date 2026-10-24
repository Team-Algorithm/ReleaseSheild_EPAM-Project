#!/usr/bin/env node
import React from 'react';
import { render } from 'ink';
import { App } from './App.js';

// If stdin is not interactive, print a plain message and exit with code 1
if (!process.stdin.isTTY) {
  process.stderr.write(
    'ReleaseShield AI: The interactive terminal requires an interactive TTY.\n' +
    'Run in an interactive terminal or use non-interactive options.\n'
  );
  process.exit(1);
}

// Clean SIGINT handler
process.on('SIGINT', () => {
  process.exit(0);
});

render(<App />);
