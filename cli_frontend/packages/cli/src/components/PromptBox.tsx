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
    <Box borderStyle="round" paddingX={1} marginY={0}>
      <Text color="cyan">{'> '}</Text>
      {isDisabled ? (
        <Text dimColor>{value || ' '}</Text>
      ) : (
        <TextInput
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
  );
}
