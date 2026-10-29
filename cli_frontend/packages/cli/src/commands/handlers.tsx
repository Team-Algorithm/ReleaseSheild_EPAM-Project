import React from 'react';
import * as path from 'path';
import * as fs from 'fs';
import { Box, Text } from 'ink';
import type { CommandRegistry } from './registry.js';
import type { ToolName, ScanSummary, Finding } from '@releaseshield/core';
import { filterFindings, isGitUrl, cloneGitRepo } from '@releaseshield/core';
import { HelpScreen } from '../screens/HelpScreen.js';
import { ScanScreen } from '../screens/ScanScreen.js';
import { ResultsScreen } from '../screens/ResultsScreen.js';
import { FindingsScreen } from '../screens/FindingsScreen.js';

declare const process: {
  exit?: (code?: number) => void;
  env?: Record<string, string | undefined>;
};

export interface CommandHandlerContext {
  registry: CommandRegistry;
  setOutput: (node: React.ReactNode | null) => void;
  exitApp: () => void;
  setPromptDisabled: (disabled: boolean) => void;
  onScanComplete: (summary: ScanSummary) => void;
  getLastSummary: () => ScanSummary | null;
  getLastFindings?: () => Finding[];
  getCurrentRepo?: () => string;
  setCurrentRepo?: (repo: string) => void;
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

  // /repo — select or inspect target repository
  registry.register({
    name: 'repo',
    description: 'View or set the target repository path to scan',
    usage: '/repo [path-or-github-url]',
    handler: (cmd) => {
      const arg = cmd.args[0];
      if (!arg) {
        const current = ctx.getCurrentRepo ? ctx.getCurrentRepo() : '.';
        ctx.setOutput(
          <Box flexDirection="column">
            <Text bold color="cyan">
              Selected Repository:
            </Text>
            <Text>  {current}</Text>
            <Box marginTop={1}>
              <Text dimColor>Usage: /repo &lt;local-directory-or-github-url&gt;</Text>
            </Box>
          </Box>
        );
        return;
      }

      if (isGitUrl(arg)) {
        ctx.setOutput(
          <Box flexDirection="column">
            <Text color="yellow">Cloning remote repository {arg}...</Text>
          </Box>
        );
        const cloneRes = cloneGitRepo(arg);
        if (!cloneRes.success || !cloneRes.path) {
          ctx.setOutput(
            <Box flexDirection="column">
              <Text color="red">
                Failed to clone repository: {cloneRes.error || 'Unknown error'}
              </Text>
            </Box>
          );
          return;
        }

        ctx.setCurrentRepo?.(cloneRes.path);
        if (typeof process !== 'undefined' && process.env) {
          process.env.RELEASESHIELD_REPO = cloneRes.path;
        }

        ctx.setOutput(
          <Box flexDirection="column">
            <Text color="green">Repository cloned and selected:</Text>
            <Text bold>  {cloneRes.path}</Text>
          </Box>
        );
        return;
      }

      const resolved = path.resolve(arg);
      if (!fs.existsSync(resolved)) {
        ctx.setOutput(
          <Box flexDirection="column">
            <Text color="red">Path does not exist: {resolved}</Text>
          </Box>
        );
        return;
      }

      try {
        const stat = fs.statSync(resolved);
        if (!stat.isDirectory()) {
          ctx.setOutput(
            <Box flexDirection="column">
              <Text color="red">Path is not a directory: {resolved}</Text>
            </Box>
          );
          return;
        }
      } catch (err) {
        ctx.setOutput(
          <Box flexDirection="column">
            <Text color="red">
              Cannot access path: {err instanceof Error ? err.message : String(err)}
            </Text>
          </Box>
        );
        return;
      }

      ctx.setCurrentRepo?.(resolved);
      if (typeof process !== 'undefined' && process.env) {
        process.env.RELEASESHIELD_REPO = resolved;
      }

      ctx.setOutput(
        <Box flexDirection="column">
          <Text color="green">Repository set to:</Text>
          <Text bold>  {resolved}</Text>
        </Box>
      );
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
        process.exit?.(0);
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

  // /scan — full interactive flow
  registry.register({
    name: 'scan',
    description: 'Run a security scan with selected tools',
    usage: '/scan [--tools trivy,semgrep] [--fail <tool>]',
    handler: (cmd) => {
      // Parse --tools flag
      let preselectedTools: ToolName[] | undefined;
      const toolsFlag = cmd.flags['tools'];
      if (toolsFlag) {
        const toolsList = Array.isArray(toolsFlag) ? toolsFlag : [toolsFlag];
        const validTools: ToolName[] = [];
        for (const t of toolsList) {
          if (t === 'trivy' || t === 'semgrep' || t === 'gitleaks') {
            validTools.push(t);
          }
        }
        if (validTools.length > 0) {
          preselectedTools = validTools;
        }
      }

      // Parse --fail flag
      let failTool: ToolName | undefined;
      const failFlag = cmd.flags['fail'];
      if (typeof failFlag === 'string') {
        if (
          failFlag === 'trivy' ||
          failFlag === 'semgrep' ||
          failFlag === 'gitleaks'
        ) {
          failTool = failFlag;
        }
      }

      const targetPath = ctx.getCurrentRepo ? ctx.getCurrentRepo() : '.';

      ctx.setOutput(
        <ScanScreen
          targetPath={targetPath}
          preselectedTools={preselectedTools}
          failTool={failTool}
          onComplete={(summary) => {
            ctx.onScanComplete(summary);
          }}
          onCancel={() => {
            ctx.setPromptDisabled(false);
            ctx.setOutput(
              <Box flexDirection="column">
                <Text dimColor>Scan cancelled.</Text>
              </Box>
            );
          }}
          onPromptDisable={ctx.setPromptDisabled}
        />
      );
    }
  });

  // /results — re-shows last scan or prompts to run /scan
  registry.register({
    name: 'results',
    description: 'Show results from the latest security scan',
    usage: '/results',
    handler: () => {
      const lastSummary = ctx.getLastSummary();
      if (!lastSummary) {
        ctx.setOutput(
          <Box flexDirection="column">
            <Text dimColor>No scans yet. Run /scan to start.</Text>
          </Box>
        );
      } else {
        ctx.setOutput(<ResultsScreen summary={lastSummary} />);
      }
    }
  });

  // /findings — list security findings with optional filters & pagination
  registry.register({
    name: 'findings',
    description: 'List security findings with optional filters',
    usage: '/findings [--severity high|medium|low] [--tool trivy|semgrep|gitleaks]',
    handler: (cmd) => {
      const allFindings = ctx.getLastFindings ? ctx.getLastFindings() : [];
      let filtered = [...allFindings];

      // Filter by severity if passed
      const sevFlag = cmd.flags['severity'] ?? cmd.flags['sev'];
      const toolFlag = cmd.flags['tool'] ?? cmd.flags['tools'];

      filtered = filterFindings(filtered, {
        severity: typeof sevFlag === 'string' ? sevFlag : undefined,
        tool: typeof toolFlag === 'string' ? toolFlag : undefined
      });

      ctx.setOutput(
        <FindingsScreen
          findings={filtered}
          onPromptDisable={ctx.setPromptDisabled}
        />
      );
    }
  });
}
