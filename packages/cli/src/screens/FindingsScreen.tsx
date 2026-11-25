import React, { useState, useEffect } from 'react';
import { Box, Text, useInput, useStdout } from 'ink';
import type { Finding } from '@releaseshield/core';

export interface FindingsScreenProps {
  findings: Finding[];
  onPromptDisable?: (disabled: boolean) => void;
  initialPage?: number;
  columns?: number;
}

export function FindingsScreen({
  findings,
  onPromptDisable,
  initialPage = 1,
  columns: propColumns
}: FindingsScreenProps) {
  const [page, setPage] = useState(initialPage);
  const [isNavigating, setIsNavigating] = useState(true);

  const { stdout } = useStdout();
  const terminalWidth =
    propColumns ??
    (typeof process !== 'undefined' && process.env.COLUMNS
      ? Number(process.env.COLUMNS)
      : undefined) ??
    (stdout as any)?.columns ??
    process.stdout?.columns ??
    80;
  const isNarrow = terminalWidth < 80;

  const isNoColor = Boolean(
    typeof process !== 'undefined' &&
      process.env.NO_COLOR !== undefined &&
      process.env.NO_COLOR !== ''
  );

  const pageSize = 10;
  const totalPages = Math.max(1, Math.ceil(findings.length / pageSize));
  const currentPage = Math.min(Math.max(1, page), totalPages);

  const startIndex = (currentPage - 1) * pageSize;
  const currentFindings = findings.slice(startIndex, startIndex + pageSize);

  useEffect(() => {
    onPromptDisable?.(isNavigating && totalPages > 1);
    return () => onPromptDisable?.(false);
  }, [isNavigating, totalPages, onPromptDisable]);

  useInput((input, key) => {
    if (!isNavigating || totalPages <= 1) return;

    if (input === 'n' || key.downArrow || key.rightArrow) {
      setPage((prev) => Math.min(totalPages, prev + 1));
    } else if (input === 'p' || key.upArrow || key.leftArrow) {
      setPage((prev) => Math.max(1, prev - 1));
    } else if (key.escape || key.return || input === 'q') {
      setIsNavigating(false);
      onPromptDisable?.(false);
    }
  });

  const sevColWidth = isNarrow ? 8 : 10;
  const toolColWidth = isNarrow ? 9 : 11;
  const ruleColWidth = isNarrow ? 22 : 34;
  const dividerWidth = Math.max(30, Math.min(76, terminalWidth - 2));

  return (
    <Box flexDirection="column">
      {/* Table Header */}
      <Box flexDirection="row">
        <Text bold>{'Severity'.padEnd(sevColWidth)}</Text>
        <Text bold>{'Tool'.padEnd(toolColWidth)}</Text>
        <Text bold>{'Rule'.padEnd(ruleColWidth)}</Text>
        <Text bold>{'Location'}</Text>
      </Box>

      {/* Header rule */}
      <Box marginY={0}>
        <Text dimColor={!isNoColor}>{'─'.repeat(dividerWidth)}</Text>
      </Box>

      {/* Rows */}
      {currentFindings.length === 0 ? (
        <Box marginY={1}>
          <Text dimColor={!isNoColor}>No findings matching the specified filters.</Text>
        </Box>
      ) : (
        currentFindings.map((f, i) => {
          const sevCapitalized =
            f.severity.charAt(0).toUpperCase() + f.severity.slice(1);
          const toolCapitalized =
            f.tool.charAt(0).toUpperCase() + f.tool.slice(1);
          const locStr = f.line ? `${f.location}:${f.line}` : f.location;

          const ruleStr =
            f.rule.length > ruleColWidth - 2
              ? f.rule.slice(0, ruleColWidth - 3) + '…'
              : f.rule;

          let sevColor: 'red' | 'yellow' | undefined;
          if (!isNoColor) {
            if (f.severity === 'high') sevColor = 'red';
            else if (f.severity === 'medium') sevColor = 'yellow';
          }

          return (
            <Box key={`${f.rule}-${startIndex + i}`} flexDirection="row">
              <Text color={sevColor} bold={f.severity === 'high'}>
                {sevCapitalized.padEnd(sevColWidth)}
              </Text>
              <Text>{toolCapitalized.padEnd(toolColWidth)}</Text>
              <Text>{ruleStr.padEnd(ruleColWidth)}</Text>
              <Text dimColor={!isNoColor}>{locStr}</Text>
            </Box>
          );
        })
      )}

      {/* Footer */}
      <Box marginTop={1} flexDirection="row">
        <Text dimColor={!isNoColor}>
          {findings.length === 0
            ? '0 findings'
            : `page ${currentPage} of ${totalPages} (${findings.length} total)`}
          {totalPages > 1 && isNavigating
            ? '   [n] next   [p] prev   [Enter/Esc] exit'
            : ''}
        </Text>
      </Box>
    </Box>
  );
}
