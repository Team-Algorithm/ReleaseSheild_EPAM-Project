import React, { useState, useMemo, useCallback } from 'react';
import * as path from 'node:path';
import * as fsSync from 'node:fs';
import { Box, Text, useApp, useInput } from 'ink';
import type { ScanSummary, Finding } from '@releaseshield/core';
import { readSarifFile, extractFindings } from '@releaseshield/core';
import { Header } from './components/Header.js';
import { StatusBar } from './components/StatusBar.js';
import { MainArea } from './components/MainArea.js';
import { PromptBox } from './components/PromptBox.js';
import { HintLine } from './components/HintLine.js';
import { parseCommand } from './commands/parser.js';
import { CommandRegistry } from './commands/registry.js';
import { registerDefaultCommands } from './commands/handlers.js';

export function resolveRepoName(targetPath?: string): string {
  if (typeof process !== 'undefined' && process.env?.RELEASESHIELD_REPO) {
    return process.env.RELEASESHIELD_REPO;
  }

  try {
    const cwd = typeof process !== 'undefined' && process.cwd ? process.cwd() : '.';
    const target = targetPath && targetPath !== '.' ? targetPath : cwd;
    const resolved = path.resolve(target);

    // If running from inside cli_frontend and parent is the root project
    if (
      path.basename(resolved).toLowerCase() === 'cli_frontend' &&
      (fsSync.existsSync(path.resolve(resolved, '..', '.git')) ||
        fsSync.existsSync(path.resolve(resolved, '..', 'package.json')))
    ) {
      return path.basename(path.resolve(resolved, '..'));
    }

    const base = path.basename(resolved);
    return base || '.';
  } catch {
    return targetPath || '.';
  }
}

export function resolveGitBranch(): string {
  try {
    const headPath = path.resolve('.git', 'HEAD');
    if (fsSync.existsSync(headPath)) {
      const head = fsSync.readFileSync(headPath, 'utf8').trim();
      if (head.startsWith('ref: refs/heads/')) {
        return head.replace('ref: refs/heads/', '');
      }
      return head.slice(0, 7);
    }
  } catch {
    // fallback
  }
  return 'main';
}

export function App() {
  const { exit } = useApp();

  useInput((input, key) => {
    if (key.ctrl && input === 'c') {
      exit();
      if (typeof process !== 'undefined' && process.exit) {
        process.exit(0);
      }
    }
  });

  const [outputNode, setOutputNode] = useState<React.ReactNode | null>(null);
  const [promptDisabled, setPromptDisabled] = useState(false);
  const [lastScan, setLastScan] = useState<string>('none');
  const [lastSummary, setLastSummary] = useState<ScanSummary | null>(null);
  const [lastFindings, setLastFindings] = useState<Finding[]>([]);
  const [currentRepoPath, setCurrentRepoPath] = useState<string>(() => {
    return typeof process !== 'undefined' && process.cwd ? process.cwd() : '.';
  });
  const [currentBranch] = useState<string>(() => resolveGitBranch());

  const handleScanComplete = useCallback((summary: ScanSummary, targetPath?: string) => {
    setLastSummary(summary);
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
    setLastScan(timeStr);

    if (targetPath) {
      setCurrentRepoPath(path.resolve(targetPath));
    }

    // Ingest real SARIF findings if a SARIF report was created
    if (summary.savedPath) {
      readSarifFile(summary.savedPath)
        .then((sarifLog) => {
          const findings = extractFindings(sarifLog);
          setLastFindings(findings);
        })
        .catch(() => {
          setLastFindings([]);
        });
    }
  }, []);

  const registry = useMemo(() => {
    const reg = new CommandRegistry();
    registerDefaultCommands(reg, {
      registry: reg,
      setOutput: (node) => setOutputNode(node),
      exitApp: () => exit(),
      setPromptDisabled,
      onScanComplete: handleScanComplete,
      getLastSummary: () => lastSummary,
      getLastFindings: () => lastFindings
    });
    return reg;
  }, [exit, handleScanComplete, lastSummary, lastFindings]);

  const handleCommandSubmit = (input: string) => {
    const parsed = parseCommand(input);
    if (!parsed.name) return;

    const command = registry.get(parsed.name);
    if (command) {
      command.handler(parsed);
    } else {
      const closest = registry.suggestClosest(parsed.name);
      setOutputNode(
        <Box flexDirection="column" marginY={1}>
          <Text color="red">Unknown command: /{parsed.name}</Text>
          {closest ? (
            <Text color="yellow">Did you mean /{closest.name}?</Text>
          ) : (
            <Text dimColor>Type /help to see available commands.</Text>
          )}
        </Box>
      );
    }
  };

  return (
    <Box flexDirection="column" paddingX={2} width="100%">
      <Header />
      <MainArea lastCommandOutput={outputNode} />
      <PromptBox onSubmit={handleCommandSubmit} isDisabled={promptDisabled} />
      <HintLine />
      <StatusBar repo={currentRepoPath} branch={currentBranch} />
    </Box>
  );
}
