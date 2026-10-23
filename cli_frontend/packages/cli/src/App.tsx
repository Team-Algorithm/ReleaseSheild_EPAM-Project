import React, { useState, useMemo } from 'react';
import { Box, Text } from 'ink';
import { Header } from './components/Header.js';
import { StatusBar } from './components/StatusBar.js';
import { MainArea } from './components/MainArea.js';
import { PromptBox } from './components/PromptBox.js';
import { HintLine } from './components/HintLine.js';
import { Divider } from './components/Divider.js';
import { parseCommand } from './commands/parser.js';
import { CommandRegistry, type CommandEntry } from './commands/registry.js';

export function App() {
  const [outputNode, setOutputNode] = useState<React.ReactNode | null>(null);

  const registry = useMemo(() => {
    const reg = new CommandRegistry();

    const sampleCommands: Array<Omit<CommandEntry, 'handler'> & { handler?: CommandEntry['handler'] }> = [
      {
        name: 'scan',
        description: 'Run a security scan with selected tools',
        usage: '/scan [--tools trivy,semgrep] [--fail <tool>]'
      },
      {
        name: 'results',
        description: 'Show results from the latest security scan',
        usage: '/results'
      },
      {
        name: 'findings',
        description: 'List security findings with optional filters',
        usage: '/findings [--severity high|medium|low] [--tool <tool>]'
      },
      {
        name: 'tools',
        description: 'Show status of configured scanning tools',
        usage: '/tools'
      },
      {
        name: 'export',
        description: 'Export scan results to SARIF format',
        usage: '/export'
      },
      {
        name: 'help',
        description: 'Display available commands and usage information',
        usage: '/help'
      },
      {
        name: 'clear',
        description: 'Clear the terminal output area',
        usage: '/clear'
      },
      {
        name: 'quit',
        description: 'Exit ReleaseShield',
        usage: '/quit'
      }
    ];

    for (const cmd of sampleCommands) {
      reg.register({
        name: cmd.name,
        description: cmd.description,
        usage: cmd.usage,
        handler: (parsed) => {
          setOutputNode(
            <Box flexDirection="column">
              <Text bold color="green">
                Command executed: /{parsed.name}
              </Text>
              <Text dimColor>Raw input: {parsed.raw}</Text>
              <Text>Arguments: {parsed.args.length > 0 ? parsed.args.join(', ') : 'none'}</Text>
              <Text>Flags: {Object.keys(parsed.flags).length > 0 ? JSON.stringify(parsed.flags) : 'none'}</Text>
            </Box>
          );
        }
      });
    }

    return reg;
  }, []);

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
