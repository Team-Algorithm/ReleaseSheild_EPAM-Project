import React, { useState } from 'react';
import { Box, Text, useInput } from 'ink';
import TextInput from 'ink-text-input';

interface PromptBoxProps {
  onSubmit: (input: string) => void;
  isDisabled?: boolean;
}

export function PromptBox({ onSubmit, isDisabled = false }: PromptBoxProps) {
  const [value, setValue] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const [tempInput, setTempInput] = useState('');

  useInput((input, key) => {
    if (isDisabled) return;

    if (key.upArrow) {
      if (history.length === 0) return;

      if (historyIndex === -1) {
        setTempInput(value);
        const newIndex = history.length - 1;
        setHistoryIndex(newIndex);
        setValue(history[newIndex]);
      } else if (historyIndex > 0) {
        const newIndex = historyIndex - 1;
        setHistoryIndex(newIndex);
        setValue(history[newIndex]);
      }
    } else if (key.downArrow) {
      if (historyIndex === -1) return;

      if (historyIndex < history.length - 1) {
        const newIndex = historyIndex + 1;
        setHistoryIndex(newIndex);
        setValue(history[newIndex]);
      } else {
        setHistoryIndex(-1);
        setValue(tempInput);
      }
    }
  });

  const handleSubmit = (submittedValue: string) => {
    const trimmed = submittedValue.trim();
    if (!trimmed) {
      setValue('');
      return;
    }

    setHistory((prev) => [...prev, trimmed]);
    setHistoryIndex(-1);
    setTempInput('');
    setValue('');
    onSubmit(trimmed);
  };

  return (
    <Box flexDirection="column" width="100%">
      {/* Sleek Input Card container inspired by OpenCode */}
      <Box
        flexDirection="column"
        borderStyle="round"
        borderColor="gray"
        paddingX={1}
        paddingY={0}
        width="100%"
      >
        <Box flexDirection="row" alignItems="center">
          <Text color="cyan" bold>{'│ '}</Text>
          {isDisabled ? (
            <Text dimColor>{value || ' '}</Text>
          ) : (
            <TextInput
              placeholder='Enter command or path to scan... e.g. /scan ./src'
              value={value}
              onChange={(val) => {
                setValue(val);
                if (historyIndex !== -1) {
                  setHistoryIndex(-1);
                }
              }}
              onSubmit={handleSubmit}
            />
          )}
        </Box>
        <Box flexDirection="row" marginTop={0} paddingLeft={2}>
          <Text color="blue" bold>Engine </Text>
          <Text dimColor>· Trivy (SCA) + Semgrep (SAST) + Gitleaks (Secrets)</Text>
        </Box>
      </Box>

      {/* Right-aligned shortcut key: ctrl+c exit ONLY */}
      <Box justifyContent="flex-end" width="100%" marginTop={0}>
        <Text dimColor>ctrl+c exit</Text>
      </Box>
    </Box>
  );
}
