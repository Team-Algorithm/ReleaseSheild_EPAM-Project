import React, { useState, useMemo } from 'react';
import { Box, Text, useApp } from 'ink';
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

  const registry = useMemo(() => {
    const reg = new CommandRegistry();
    registerDefaultCommands(reg, {
      registry: reg,
      setOutput: (node) => setOutputNode(node),
      exitApp: () => exit()
    });
    return reg;
  }, [exit]);

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
      <StatusBar repo="./NodeGoat" tools="trivy, semgrep, gitleaks" lastScan="none" />
      <Divider />
      <MainArea lastCommandOutput={outputNode} />
      <Divider />
      <PromptBox onSubmit={handleCommandSubmit} />
      <HintLine />
    </Box>
  );
}
