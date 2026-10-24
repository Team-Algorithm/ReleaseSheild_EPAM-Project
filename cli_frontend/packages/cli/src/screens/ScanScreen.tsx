import React, { useState, useEffect, useCallback } from 'react';
import { Box, Text, useInput } from 'ink';
import Spinner from 'ink-spinner';
import type { ToolName, ToolUpdate, ScanSummary } from '@releaseshield/core';
import { runScan } from '@releaseshield/core';

type ScanPhase = 'selecting' | 'running' | 'complete';

interface ToolSelection {
  name: ToolName;
  label: string;
  selected: boolean;
}

const ALL_TOOLS: ToolSelection[] = [
  { name: 'trivy', label: 'Trivy', selected: true },
  { name: 'semgrep', label: 'Semgrep', selected: true },
  { name: 'gitleaks', label: 'Gitleaks', selected: true }
];

interface ToolState {
  status: 'waiting' | 'running' | 'done' | 'issues_found' | 'failed';
  elapsedSec: number;
  error?: string;
}

export interface ScanScreenProps {
  preselectedTools?: ToolName[];
  failTool?: ToolName;
  onComplete: (summary: ScanSummary) => void;
  onCancel: () => void;
  onPromptDisable: (disabled: boolean) => void;
}

export function ScanScreen({
  preselectedTools,
  failTool,
  onComplete,
  onCancel,
  onPromptDisable
}: ScanScreenProps) {
  const [phase, setPhase] = useState<ScanPhase>(
    preselectedTools ? 'running' : 'selecting'
  );
  const [tools, setTools] = useState<ToolSelection[]>(() => {
    if (preselectedTools) {
      return ALL_TOOLS.map((t) => ({
        ...t,
        selected: preselectedTools.includes(t.name)
      }));
    }
    return ALL_TOOLS.map((t) => ({ ...t }));
  });
  const [cursorIndex, setCursorIndex] = useState(0);
  const [toolStates, setToolStates] = useState<Record<string, ToolState>>({});
  const [summary, setSummary] = useState<ScanSummary | null>(null);

  // Disable prompt during selecting and running phases
  useEffect(() => {
    onPromptDisable(phase === 'selecting' || phase === 'running');
    return () => onPromptDisable(false);
  }, [phase, onPromptDisable]);

  // Start scan when transitioning to running phase
  const startScan = useCallback(
    (selectedTools: ToolName[]) => {
      // Initialize tool states
      const initialStates: Record<string, ToolState> = {};
      for (const t of selectedTools) {
        initialStates[t] = { status: 'waiting', elapsedSec: 0 };
      }
      setToolStates(initialStates);
      setPhase('running');

      const handleUpdate = (update: ToolUpdate) => {
        setToolStates((prev) => ({
          ...prev,
          [update.tool]: {
            status: update.status,
            elapsedSec: update.elapsedSec,
            error: update.error
          }
        }));
      };

      runScan(selectedTools, handleUpdate, { failTool }).then((result) => {
        setSummary(result);
        setPhase('complete');
        onComplete(result);
      });
    },
    [failTool, onComplete]
  );

  // Auto-start if tools were preselected
  useEffect(() => {
    if (preselectedTools && phase === 'running' && !summary) {
      startScan(preselectedTools);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Handle keyboard input for tool selection checklist
  useInput((input, key) => {
    if (phase !== 'selecting') return;

    if (key.upArrow) {
      setCursorIndex((prev) => (prev > 0 ? prev - 1 : tools.length - 1));
    } else if (key.downArrow) {
      setCursorIndex((prev) => (prev < tools.length - 1 ? prev + 1 : 0));
    } else if (input === ' ') {
      setTools((prev) =>
        prev.map((t, i) =>
          i === cursorIndex ? { ...t, selected: !t.selected } : t
        )
      );
    } else if (key.return) {
      const selectedTools = tools.filter((t) => t.selected).map((t) => t.name);
      if (selectedTools.length === 0) return; // Don't start with no tools
      startScan(selectedTools);
    } else if (key.escape) {
      onCancel();
    }
  });

  // PHASE 1: Tool selection checklist
  if (phase === 'selecting') {
    return (
      <Box flexDirection="column">
        <Text bold color="cyan">
          Select tools
        </Text>
        <Box flexDirection="column" marginTop={1}>
          {tools.map((tool, index) => (
            <Box key={tool.name} flexDirection="row">
              <Text color={index === cursorIndex ? 'cyan' : undefined}>
                {index === cursorIndex ? '❯ ' : '  '}
              </Text>
              <Text color={tool.selected ? 'green' : 'gray'}>
                {tool.selected ? '[✓]' : '[ ]'}
              </Text>
              <Text> {tool.label}</Text>
            </Box>
          ))}
        </Box>
        <Box marginTop={1}>
          <Text dimColor>
            ↑ ↓ move   Space toggle   Enter scan   Esc cancel
          </Text>
        </Box>
      </Box>
    );
  }

  // PHASE 2: Running scan with live progress
  if (phase === 'running') {
    const toolColWidth = 14;
    const statusColWidth = 12;

    return (
      <Box flexDirection="column">
        <Text bold color="cyan">
          Scanning…
        </Text>
        <Box flexDirection="column" marginTop={1}>
          {Object.entries(toolStates).map(([toolName, state]) => {
            const label =
              toolName.charAt(0).toUpperCase() + toolName.slice(1);
            return (
              <Box key={toolName} flexDirection="row">
                {state.status === 'running' ? (
                  <Box marginRight={1}>
                    <Text color="cyan">
                      <Spinner type="dots" />
                    </Text>
                  </Box>
                ) : state.status === 'done' ? (
                  <Text color="green">{'✓ '}</Text>
                ) : state.status === 'failed' ? (
                  <Text color="red">{'✗ '}</Text>
                ) : (
                  <Text dimColor>{'○ '}</Text>
                )}
                <Text>{label.padEnd(toolColWidth)}</Text>
                {state.status === 'running' ? (
                  <>
                    <Text color="yellow">
                      {'running'.padEnd(statusColWidth)}
                    </Text>
                    <Text>{state.elapsedSec.toFixed(1)}s</Text>
                  </>
                ) : state.status === 'done' ? (
                  <>
                    <Text color="green">
                      {'done'.padEnd(statusColWidth)}
                    </Text>
                    <Text>{state.elapsedSec.toFixed(1)}s</Text>
                  </>
                ) : state.status === 'failed' ? (
                  <>
                    <Text color="red">
                      {'failed'.padEnd(statusColWidth)}
                    </Text>
                    <Text color="red">{state.error ?? 'unknown error'}</Text>
                  </>
                ) : (
                  <Text dimColor>
                    {'waiting'.padEnd(statusColWidth)}
                  </Text>
                )}
              </Box>
            );
          })}
        </Box>
      </Box>
    );
  }

  // PHASE 3: Scan complete - show summary
  if (phase === 'complete' && summary) {
    const toolColWidth = 14;
    const numColWidth = 9;
    const dividerWidth = toolColWidth + numColWidth * 4;

    return (
      <Box flexDirection="column">
        <Text bold color="green">
          Scan complete
        </Text>

        {/* Tool status lines */}
        <Box flexDirection="column" marginTop={1} marginBottom={1}>
          {summary.tools.map((toolResult) => {
            const label =
              toolResult.tool.charAt(0).toUpperCase() +
              toolResult.tool.slice(1);
            return (
              <Box key={toolResult.tool} flexDirection="row">
                {toolResult.status === 'done' ? (
                  <Text color="green">{'✓ '}</Text>
                ) : (
                  <Text color="red">{'✗ '}</Text>
                )}
                <Text>{label.padEnd(toolColWidth)}</Text>
                {toolResult.status === 'done' ? (
                  <>
                    <Text color="green">{'done'.padEnd(12)}</Text>
                    <Text>
                      {toolResult.durationSec.toFixed(1).padStart(5)}s
                    </Text>
                  </>
                ) : (
                  <>
                    <Text color="red">{'failed'.padEnd(12)}</Text>
                    <Text color="red">
                      {toolResult.error ?? 'unknown error'}
                    </Text>
                  </>
                )}
              </Box>
            );
          })}
        </Box>

        {/* Results Table */}
        <Box flexDirection="column">
          <Box flexDirection="row">
            <Text bold>{'Tool'.padEnd(toolColWidth)}</Text>
            <Text bold color="red">
              {'High'.padStart(numColWidth)}
            </Text>
            <Text bold color="yellow">
              {'Medium'.padStart(numColWidth)}
            </Text>
            <Text bold>{'Low'.padStart(numColWidth)}</Text>
            <Text bold>{'Total'.padStart(numColWidth)}</Text>
          </Box>

          {summary.tools
            .filter((t) => t.status === 'done')
            .map((toolResult) => {
              const label =
                toolResult.tool.charAt(0).toUpperCase() +
                toolResult.tool.slice(1);
              const total =
                toolResult.counts.high +
                toolResult.counts.medium +
                toolResult.counts.low;
              return (
                <Box key={toolResult.tool} flexDirection="row">
                  <Text>{label.padEnd(toolColWidth)}</Text>
                  <Text color="red">
                    {String(toolResult.counts.high).padStart(numColWidth)}
                  </Text>
                  <Text color="yellow">
                    {String(toolResult.counts.medium).padStart(numColWidth)}
                  </Text>
                  <Text>
                    {String(toolResult.counts.low).padStart(numColWidth)}
                  </Text>
                  <Text>{String(total).padStart(numColWidth)}</Text>
                </Box>
              );
            })}

          <Box marginY={0}>
            <Text dimColor>{'─'.repeat(dividerWidth)}</Text>
          </Box>

          {(() => {
            const total =
              summary.totalCounts.high +
              summary.totalCounts.medium +
              summary.totalCounts.low;
            return (
              <Box flexDirection="row">
                <Text bold>{'Total'.padEnd(toolColWidth)}</Text>
                <Text bold color="red">
                  {String(summary.totalCounts.high).padStart(numColWidth)}
                </Text>
                <Text bold color="yellow">
                  {String(summary.totalCounts.medium).padStart(numColWidth)}
                </Text>
                <Text bold>
                  {String(summary.totalCounts.low).padStart(numColWidth)}
                </Text>
                <Text bold>{String(total).padStart(numColWidth)}</Text>
              </Box>
            );
          })()}
        </Box>

        {/* Summary footer */}
        <Box flexDirection="column" marginTop={1}>
          <Text>Total time: {summary.totalDurationSec}s</Text>
          <Box marginTop={1}>
            <Text dimColor>Saved: {summary.savedPath}</Text>
          </Box>
        </Box>
      </Box>
    );
  }

  return null;
}
