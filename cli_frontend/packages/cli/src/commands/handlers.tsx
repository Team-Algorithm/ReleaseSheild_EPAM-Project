import React from 'react';
import { Box, Text } from 'ink';
import type { CommandRegistry } from './registry.js';
import { HelpScreen } from '../screens/HelpScreen.js';

export interface CommandHandlerContext {
  registry: CommandRegistry;
  setOutput: (node: React.ReactNode | null) => void;
  exitApp: () => void;
}

export function registerDefaultCommands(
  registry: CommandRegistry,
  ctx: CommandHandlerContext
): void {
  // /help
  registry.register({
    name: 'help',
    description: 'Show help and available commands',
    usage: '/help',
    handler: () => {
      ctx.setOutput(<HelpScreen commands={registry.getAll()} />);
    }
  });

  // /clear
  registry.register({
    name: 'clear',
    description: 'Clear the terminal output area',
    usage: '/clear',
    handler: () => {
      ctx.setOutput(null);
    }
  });

  // /quit
  registry.register({
    name: 'quit',
    description: 'Exit ReleaseShield',
    usage: '/quit',
    handler: () => {
      ctx.setOutput(
        <Box flexDirection="column">
          <Text dimColor>Exiting ReleaseShield. Goodbye!</Text>
        </Box>
      );
      setTimeout(() => {
        ctx.exitApp();
      }, 50);
    }
  });

  // /tools
  registry.register({
    name: 'tools',
    description: 'Show status of configured scanning tools',
    usage: '/tools',
    handler: () => {
      ctx.setOutput(
        <Box flexDirection="column">
          <Text bold color="cyan">
            Configured Scanning Tools
          </Text>
          <Box flexDirection="column" marginTop={1}>
            <Box flexDirection="row">
              <Text bold color="white">
                {'trivy'.padEnd(14)}
              </Text>
              <Text color="green">{'ready'.padEnd(10)}</Text>
              <Text dimColor>Vulnerabilities & misconfigurations</Text>
            </Box>
            <Box flexDirection="row">
              <Text bold color="white">
                {'semgrep'.padEnd(14)}
              </Text>
              <Text color="green">{'ready'.padEnd(10)}</Text>
              <Text dimColor>Static analysis & SAST rules</Text>
            </Box>
            <Box flexDirection="row">
              <Text bold color="white">
                {'gitleaks'.padEnd(14)}
              </Text>
              <Text color="green">{'ready'.padEnd(10)}</Text>
              <Text dimColor>Hardcoded secrets & credential detection</Text>
            </Box>
          </Box>
        </Box>
      );
    }
  });

  // /export
  registry.register({
    name: 'export',
    description: 'Export scan results to SARIF format',
    usage: '/export',
    handler: () => {
      ctx.setOutput(
        <Box flexDirection="column">
          <Text color="yellow">Export is available in a later phase.</Text>
        </Box>
      );
    }
  });

  // /scan stub (to be fully replaced in Step 6)
  registry.register({
    name: 'scan',
    description: 'Run a security scan with selected tools',
    usage: '/scan [--tools trivy,semgrep] [--fail <tool>]',
    handler: (cmd) => {
      ctx.setOutput(
        <Box flexDirection="column">
          <Text color="green">Scan triggered: /{cmd.raw}</Text>
          <Text dimColor>Full interactive scan checklist and flow available in Step 6.</Text>
        </Box>
      );
    }
  });

  // /results stub (to be fully replaced in Step 7)
  registry.register({
    name: 'results',
    description: 'Show results from the latest security scan',
    usage: '/results',
    handler: () => {
      ctx.setOutput(
        <Box flexDirection="column">
          <Text dimColor>No scans yet. Run /scan to start.</Text>
        </Box>
      );
    }
  });

  // /findings stub (to be fully replaced in Step 8)
  registry.register({
    name: 'findings',
    description: 'List security findings with optional filters',
    usage: '/findings [--severity high|medium|low] [--tool <tool>]',
    handler: () => {
      ctx.setOutput(
        <Box flexDirection="column">
          <Text dimColor>Findings view available in Step 8.</Text>
        </Box>
      );
    }
  });
}
