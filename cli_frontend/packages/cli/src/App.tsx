import React from 'react';
import { Box } from 'ink';
import { Header } from './components/Header.js';
import { StatusBar } from './components/StatusBar.js';
import { MainArea } from './components/MainArea.js';
import { PromptBox } from './components/PromptBox.js';
import { HintLine } from './components/HintLine.js';
import { Divider } from './components/Divider.js';

export function App() {
  return (
    <Box flexDirection="column" paddingX={1} width="100%">
      <Header />
      <Divider />
      <StatusBar repo="./NodeGoat" tools="trivy, semgrep, gitleaks" lastScan="none" />
      <Divider />
      <MainArea />
      <Divider />
      <PromptBox />
      <HintLine />
    </Box>
  );
}
