import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render } from 'ink-testing-library';
import { ScanScreen } from '../src/screens/ScanScreen.js';
import * as core from '@releaseshield/core';
import type { ScanSummary } from '@releaseshield/core';
import { CommandRegistry } from '../src/commands/registry.js';
import { registerDefaultCommands } from '../src/commands/handlers.js';
import { parseCommand } from '../src/commands/parser.js';
import { resolveRepoName } from '../src/App.js';

describe('ScanScreen and interactive scan command', () => {
  const dummySummary: ScanSummary = {
    tools: [
      {
        tool: 'trivy',
        status: 'done',
        durationSec: 1.0,
        counts: { high: 0, medium: 0, low: 0 }
      },
      {
        tool: 'gitleaks',
        status: 'done',
        durationSec: 0.5,
        counts: { high: 0, medium: 0, low: 0 }
      }
    ],
    totalCounts: { high: 0, medium: 0, low: 0 },
    totalDurationSec: 1.5,
    savedPath: './results/result.sarif'
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders default tool selection checklist with Trivy and Gitleaks selected, and Semgrep unselected', () => {
    const { lastFrame } = render(
      <ScanScreen
        onComplete={() => {}}
        onCancel={() => {}}
        onPromptDisable={() => {}}
      />
    );
    const frame = lastFrame() ?? '';

    expect(frame).toContain('Select tools');
    expect(frame).toContain('[✓] Trivy');
    expect(frame).toContain('[ ] Semgrep');
    expect(frame).toContain('[✓] Gitleaks');
  });

  it('forwards targetPath to runScan when preselected tools are provided', async () => {
    const runScanSpy = vi
      .spyOn(core, 'runScan')
      .mockResolvedValue(dummySummary);

    render(
      <ScanScreen
        targetPath={'D:\\Gitshit\\ThreatLens'}
        preselectedTools={['trivy', 'gitleaks']}
        onComplete={() => {}}
        onCancel={() => {}}
        onPromptDisable={() => {}}
      />
    );

    expect(runScanSpy).toHaveBeenCalledWith(
      ['trivy', 'gitleaks'],
      expect.any(Function),
      expect.objectContaining({
        targetPath: 'D:\\Gitshit\\ThreatLens'
      })
    );
  });

  it('forwards targetPath when Enter is pressed in interactive checklist mode', async () => {
    const runScanSpy = vi
      .spyOn(core, 'runScan')
      .mockResolvedValue(dummySummary);

    const { stdin } = render(
      <ScanScreen
        targetPath="./my-repo"
        onComplete={() => {}}
        onCancel={() => {}}
        onPromptDisable={() => {}}
      />
    );

    // Press return/enter to start scan with default selections (trivy and gitleaks)
    stdin.write('\r');

    expect(runScanSpy).toHaveBeenCalledWith(
      ['trivy', 'gitleaks'],
      expect.any(Function),
      expect.objectContaining({
        targetPath: './my-repo'
      })
    );
  });

  it('handlers /scan extracts positional target path including Windows backslash path', () => {
    const registry = new CommandRegistry();
    let renderedElement: React.ReactElement | null = null;
    const fakeCtx = {
      setOutput: (element: React.ReactElement) => {
        renderedElement = element;
      },
      getLastScan: () => null,
      onScanComplete: () => {},
      setPromptDisabled: () => {},
      exit: () => {}
    };

    registerDefaultCommands(registry, fakeCtx);

    const scanCmd = registry.get('scan');
    expect(scanCmd).toBeDefined();

    // Test with Windows drive letter and backslashes
    const parsed = parseCommand('/scan D:\\Projects\\Repo1 --fail trivy');
    scanCmd!.handler(parsed);

    expect(renderedElement).not.toBeNull();
    const props = (renderedElement as any).props;
    expect(props.targetPath).toBe('D:\\Projects\\Repo1');
    expect(props.failTool).toBe('trivy');
  });

  it('handlers /scan preserves default behavior when no target path is supplied', () => {
    const registry = new CommandRegistry();
    let renderedElement: React.ReactElement | null = null;
    const fakeCtx = {
      setOutput: (element: React.ReactElement) => {
        renderedElement = element;
      },
      getLastScan: () => null,
      onScanComplete: () => {},
      setPromptDisabled: () => {},
      exit: () => {}
    };

    registerDefaultCommands(registry, fakeCtx);

    const scanCmd = registry.get('scan');
    const parsed = parseCommand('/scan');
    scanCmd!.handler(parsed);

    expect(renderedElement).not.toBeNull();
    const props = (renderedElement as any).props;
    expect(props.targetPath).toBeUndefined();
  });

  it('handlers /scan forwards targetPath to onComplete callback', () => {
    const registry = new CommandRegistry();
    let completedTargetPath: string | undefined;
    const fakeCtx = {
      setOutput: (element: React.ReactElement) => {
        // Trigger onComplete on the rendered ScanScreen
        const props = (element as any).props;
        props.onComplete(dummySummary);
      },
      getLastScan: () => null,
      onScanComplete: (_summary: any, targetPath?: string) => {
        completedTargetPath = targetPath;
      },
      setPromptDisabled: () => {},
      exit: () => {}
    };

    registerDefaultCommands(registry, fakeCtx);
    const scanCmd = registry.get('scan');
    const parsed = parseCommand('/scan D:\\Gitshit\\ThreatLens');
    scanCmd!.handler(parsed);

    expect(completedTargetPath).toBe('D:\\Gitshit\\ThreatLens');
  });
});

describe('resolveRepoName', () => {
  const originalEnv = process.env.RELEASESHIELD_REPO;

  afterEach(() => {
    if (originalEnv !== undefined) {
      process.env.RELEASESHIELD_REPO = originalEnv;
    } else {
      delete process.env.RELEASESHIELD_REPO;
    }
  });

  it('uses RELEASESHIELD_REPO environment variable when defined', () => {
    process.env.RELEASESHIELD_REPO = 'custom-repo-env';
    expect(resolveRepoName()).toBe('custom-repo-env');
    expect(resolveRepoName('/another/path')).toBe('custom-repo-env');
  });

  it('extracts basename for custom target paths', () => {
    delete process.env.RELEASESHIELD_REPO;
    expect(resolveRepoName('D:\\Gitshit\\ThreatLens')).toBe('ThreatLens');
    expect(resolveRepoName('./NodeGoat')).toBe('NodeGoat');
  });

  it('resolves actual repository name for current workspace default (.)', () => {
    delete process.env.RELEASESHIELD_REPO;
    const name = resolveRepoName('.');
    expect(name).toBe('ReleaseSheild_EPAM-Project');
  });
});
