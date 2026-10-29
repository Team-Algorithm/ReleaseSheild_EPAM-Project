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
import { Divider } from './components/Divider.js';
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
  const [activeTools, setActiveTools] = useState<string>('trivy, semgrep, gitleaks');
  const [currentRepo, setCurrentRepo] = useState<string>(() => resolveRepoName());

  const handleScanComplete = useCallback((summary: ScanSummary, targetPath?: string) => {
    setLastSummary(summary);
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
    setLastScan(timeStr);
    const toolNames = summary.tools.map((t) => t.tool).join(', ');
    setActiveTools(toolNames);

    if (targetPath) {
      setCurrentRepo(resolveRepoName(targetPath));
    }

    // Ingest real SARIF findings if a SARIF report was created
    if (summary.savedPath) {
      readSarifFile(summary.savedPath)
        .then((sarifLog) => {
          const findings = extractFindings(sarifLog);
          setLastFindings(findings);
        })
        .catch(() => {
          // If no SARIF file on disk, findings remain empty
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
        <Box flexDirection="column">
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
    <Box flexDirection="column" paddingX={1} width="100%">
      <Header />
      <Divider />
      <StatusBar repo={currentRepo} tools={activeTools} lastScan={lastScan} />
      <Divider />
      <MainArea lastCommandOutput={outputNode} />
      <Divider />
      <PromptBox onSubmit={handleCommandSubmit} isDisabled={promptDisabled} />
      <HintLine />
    </Box>
  );
}
