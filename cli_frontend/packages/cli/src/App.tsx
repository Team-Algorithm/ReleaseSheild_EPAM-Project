import React, { useState, useMemo, useCallback } from 'react';
import { Box, Text, useApp } from 'ink';
import type { ScanSummary } from '@releaseshield/core';
import { Header } from './components/Header.js';
import { StatusBar } from './components/StatusBar.js';
import { MainArea } from './components/MainArea.js';
import { PromptBox } from './components/PromptBox.js';
import { HintLine } from './components/HintLine.js';
import { Divider } from './components/Divider.js';
import { parseCommand } from './commands/parser.js';
import { CommandRegistry } from './commands/registry.js';
import { registerDefaultCommands } from './commands/handlers.js';

export function App() {
  const { exit } = useApp();
  const [outputNode, setOutputNode] = useState<React.ReactNode | null>(null);
  const [promptDisabled, setPromptDisabled] = useState(false);
  const [lastScan, setLastScan] = useState<string>('none');
  const [lastSummary, setLastSummary] = useState<ScanSummary | null>(null);
  const [activeTools, setActiveTools] = useState<string>('trivy, semgrep, gitleaks');

  const handleScanComplete = useCallback((summary: ScanSummary) => {
    setLastSummary(summary);
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
    setLastScan(timeStr);
    const toolNames = summary.tools.map((t) => t.tool).join(', ');
    setActiveTools(toolNames);
  }, []);

  const registry = useMemo(() => {
    const reg = new CommandRegistry();
    registerDefaultCommands(reg, {
      registry: reg,
      setOutput: (node) => setOutputNode(node),
      exitApp: () => exit(),
      setPromptDisabled,
      onScanComplete: handleScanComplete,
      getLastSummary: () => lastSummary
    });
    return reg;
  }, [exit, handleScanComplete, lastSummary]);

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
      <StatusBar repo="./NodeGoat" tools={activeTools} lastScan={lastScan} />
      <Divider />
      <MainArea lastCommandOutput={outputNode} />
      <Divider />
      <PromptBox onSubmit={handleCommandSubmit} isDisabled={promptDisabled} />
      <HintLine />
    </Box>
  );
}
