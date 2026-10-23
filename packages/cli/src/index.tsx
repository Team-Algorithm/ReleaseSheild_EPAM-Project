#!/usr/bin/env node
import React from 'react';
import { render, Text } from 'ink';

export function App() {
  return (
    <Text>
      ReleaseShield AI{'\n'}v0.1
    </Text>
  );
}

render(<App />);
