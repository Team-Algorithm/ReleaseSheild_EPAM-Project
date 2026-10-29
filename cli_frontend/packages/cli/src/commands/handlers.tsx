import React from 'react';
import * as path from 'path';
import * as fs from 'fs';
import { Box, Text } from 'ink';
import type { CommandRegistry } from './registry.js';
import type { ToolName, ScanSummary, Finding } from '@releaseshield/core';
import {
  filterFindings,
  checkToolAvailability,
  isGitUrl,
  cloneGitRepo
} from '@releaseshield/core';
import { HelpScreen } from '../screens/HelpScreen.js';
import { ScanScreen } from '../screens/ScanScreen.js';
import { ResultsScreen } from '../screens/ResultsScreen.js';
import { FindingsScreen } from '../screens/FindingsScreen.js';

declare const process: {
  exit?: (code?: number) => void;
  env: Record<string, string | undefined>;
};

export interface CommandHandlerContext {
  registry: CommandRegistry;
  setOutput: (node: React.ReactNode | null) => void;
  exitApp: () => void;
  setPromptDisabled: (disabled: boolean) => void;
  onScanComplete: (summary: ScanSummary) => void;
  getLastSummary: () => ScanSummary | null;
  getLastFindings?: () => Finding[];
  getCurrentRepo: () => string;
  setCurrentRepo: (repo: string) => void;
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
    description: 'Select or show target repository path for scanning',
    usage: '/repo [path|url]',
    handler: (cmd) => {
      const target = cmd.args[0];

      if (!target) {
        const active = ctx.getCurrentRepo();
        ctx.setOutput(
          <Box flexDirection="column">
            <Text bold color="cyan">
              Repository Selection
            </Text>
            <Box marginTop={1}>
              <Text>Current repository: </Text>
              <Text bold color="green">
                {active}
              </Text>
            </Box>
            <Box marginTop={1}>
              <Text dimColor>To select a local directory: </Text>
              <Text bold color="yellow">
                /repo &lt;path-to-directory&gt;
              </Text>
            </Box>
            <Box>
              <Text dimColor>To import a remote repository: </Text>
              <Text bold color="yellow">
                /repo https://github.com/&lt;owner&gt;/&lt;repo&gt;
              </Text>
            </Box>
            <Box marginTop={1}>
              <Text dimColor>Examples: </Text>
              <Text color="gray">/repo ./my-project or /repo https://github.com/OWASP/NodeGoat</Text>
            </Box>
          </Box>
        );
        return;
      }

      // Check if argument is a remote Git or GitHub URL
      if (isGitUrl(target)) {
        const cloneResult = cloneGitRepo(target);
        if (!cloneResult.success || !cloneResult.path) {
          ctx.setOutput(
            <Box flexDirection="column">
              <Text color="red">
                Error: Failed to clone remote repository: {target}
              </Text>
              <Text dimColor>{cloneResult.error ?? 'Unknown error'}</Text>
            </Box>
          );
          return;
        }

        ctx.setCurrentRepo(cloneResult.path);
        process.env.RELEASESHIELD_REPO = cloneResult.path;

        ctx.setOutput(
          <Box flexDirection="column">
            <Text bold color="green">
              ✓ Remote repository cloned and selected
            </Text>
            <Box marginTop={1}>
              <Text>Source URL: </Text>
              <Text bold color="cyan">
                {target}
              </Text>
            </Box>
            <Box>
              <Text>Local Cache: </Text>
              <Text bold color="white">
                {cloneResult.path}
              </Text>
            </Box>
            <Box marginTop={1}>
              <Text dimColor>Type /scan to analyze this repository.</Text>
            </Box>
          </Box>
        );
        return;
      }

      const resolved = path.resolve(target);
      try {
        const stat = fs.statSync(resolved);
        if (!stat.isDirectory()) {
          ctx.setOutput(
            <Box flexDirection="column">
              <Text color="red">
                Error: Path exists but is not a directory: {target}
              </Text>
              <Text dimColor>Please provide a valid directory path.</Text>
            </Box>
          );
          return;
        }
      } catch {
        ctx.setOutput(
          <Box flexDirection="column">
            <Text color="red">
              Error: Repository path does not exist: {target}
            </Text>
            <Text dimColor>Please check the path and try again.</Text>
          </Box>
        );
        return;
      }

      ctx.setCurrentRepo(resolved);
      process.env.RELEASESHIELD_REPO = resolved;

      ctx.setOutput(
        <Box flexDirection="column">
          <Text bold color="green">
            ✓ Target repository set
          </Text>
          <Box marginTop={1}>
            <Text>Path: </Text>
            <Text bold color="cyan">
              {resolved}
            </Text>
          </Box>
          <Box marginTop={1}>
            <Text dimColor>Type /scan to analyze this repository.</Text>
          </Box>
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

  // /tools — accurate real-time scanner availability check
  registry.register({
    name: 'tools',
    description: 'Show status of configured scanning tools',
    usage: '/tools',
    handler: async () => {
      const [trivyOk, semgrepOk, gitleaksOk] = await Promise.all([
        checkToolAvailability('trivy'),
        checkToolAvailability('semgrep'),
        checkToolAvailability('gitleaks')
      ]);

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
              <Text color={trivyOk ? 'green' : 'yellow'}>
                {(trivyOk ? 'ready' : 'not installed').padEnd(16)}
              </Text>
              <Text dimColor>Vulnerabilities & misconfigurations</Text>
            </Box>
            <Box flexDirection="row">
              <Text bold color="white">
                {'semgrep'.padEnd(14)}
              </Text>
              <Text color={semgrepOk ? 'green' : 'yellow'}>
                {(semgrepOk ? 'ready' : 'not installed').padEnd(16)}
              </Text>
              <Text dimColor>Static analysis & SAST rules</Text>
            </Box>
            <Box flexDirection="row">
              <Text bold color="white">
                {'gitleaks'.padEnd(14)}
              </Text>
              <Text color={gitleaksOk ? 'green' : 'yellow'}>
                {(gitleaksOk ? 'ready' : 'not installed').padEnd(16)}
              </Text>
              <Text dimColor>Hardcoded secrets & credential detection</Text>
            </Box>
          </Box>
          {(!trivyOk || !semgrepOk || !gitleaksOk) && (
            <Box marginTop={1}>
              <Text dimColor>
                Note: Missing tools will report as failed during scans without blocking other tools.
              </Text>
            </Box>
          )}
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
      const lastSummary = ctx.getLastSummary();
      if (!lastSummary || !lastSummary.savedPath) {
        ctx.setOutput(
          <Box flexDirection="column">
            <Text color="yellow">No scan results to export. Run /scan first.</Text>
          </Box>
        );
        return;
      }

      ctx.setOutput(
        <Box flexDirection="column">
          <Text bold color="green">✓ SARIF report available</Text>
          <Box marginTop={1}>
            <Text>Location: </Text>
            <Text bold color="cyan">{path.resolve(lastSummary.savedPath)}</Text>
          </Box>
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
      // Validate current repository before scanning
      const activeRepo = ctx.getCurrentRepo();
      const resolved = path.resolve(activeRepo);
      let isDir = false;
      try {
        const stat = fs.statSync(resolved);
        isDir = stat.isDirectory();
      } catch {
        isDir = false;
      }

      if (!isDir) {
        ctx.setOutput(
          <Box flexDirection="column">
            <Text color="red">
              Error: Target repository does not exist or is not a directory: {activeRepo}
            </Text>
            <Text dimColor>Please use /repo &lt;path&gt; to select a valid directory first.</Text>
          </Box>
        );
        return;
      }

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

      ctx.setOutput(
        <ScanScreen
          targetPath={resolved}
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
