import { describe, it, expect, vi, afterEach, mocked } from 'vitest';
import {
  buildGitleaksArgs,
  runGitleaks,
  isGitleaksAvailable,
} from '../src/Scanner/gitleaks.js';

// ------------------------------------------------------------------
// Mock the tools module (provides getToolRunner & checkToolAvailability)
// ------------------------------------------------------------------
vi.mock('../src/tools.js', async () => {
  const actual = await import('../src/tools.js');
  return {
    ...actual,
    getToolRunner: vi.fn(),
    checkToolAvailability: vi.fn(),
  };
});

// Import the mocked symbols after the vi.mock call so that Vitest applies the mock.
import { getToolRunner, checkToolAvailability } from '../src/tools.js';

afterEach(() => {
  vi.resetAllMocks();
});

describe('Gitleaks wrapper', () => {
  it('delegates argument building to the runner', () => {
    const target = './my-repo';
    const out = './out.sarif';
    const fakeArgs = ['detect', '--source', target, '--report-format', 'sarif', '--report-path', out];
    // Mock a runner that returns the fake args
    const mockRunner = {
      buildArgs: vi.fn().mockReturnValue(fakeArgs),
    } as unknown as { buildArgs: ReturnType<typeof vi.fn> };
    const mockedGetToolRunner = vi.mocked(getToolRunner);
    mockedGetToolRunner.mockReturnValue(mockRunner);

    const args = buildGitleaksArgs(target, out);
    expect(mockRunner.buildArgs).toHaveBeenCalledOnce();
    expect(mockRunner.buildArgs).toHaveBeenCalledWith(target, out);
    expect(args).toBe(fakeArgs);
  });

  it('returns failure when targetPath is missing or blank', async () => {
    const result = await runGitleaks({ targetPath: '   ', outputPath: './out.sarif' });
    expect(result).toMatchObject({
      tool: 'gitleaks',
      status: 'failed',
      error: 'A target repository path is required.',
    });
  });

  it('returns failure when outputPath is missing or blank', async () => {
    const result = await runGitleaks({ targetPath: './repo', outputPath: '   ' });
    expect(result).toMatchObject({
      tool: 'gitleaks',
      status: 'failed',
      error: 'A SARIF output path is required.',
    });
  });

  it('forwards valid options to the runner', async () => {
    const mockRunResult = {
      tool: 'gitleaks' as const,
      status: 'done' as const,
      exitCode: 0,
      durationSec: 1,
      counts: { high: 0, medium: 0, low: 0 },
    };
    const mockRunner = {
      run: vi.fn().mockResolvedValue(mockRunResult),
    } as unknown as { run: ReturnType<typeof vi.fn> };
    const mockedGetToolRunner = vi.mocked(getToolRunner);
    mockedGetToolRunner.mockReturnValue(mockRunner);

    const options = { targetPath: './repo', outputPath: './out.sarif' };
    const result = await runGitleaks(options);
    expect(mockRunner.run).toHaveBeenCalledOnce();
    expect(mockRunner.run).toHaveBeenCalledWith(options);
    expect(result).toBe(mockRunResult);
  });

  it('forwards availability check to checkToolAvailability', async () => {
    const mockedCheck = vi.mocked(checkToolAvailability);
    mockedCheck.mockResolvedValue(true);
    const available = await isGitleaksAvailable();
    expect(mockedCheck).toHaveBeenCalledOnce();
    expect(mockedCheck).toHaveBeenCalledWith('gitleaks');
    expect(available).toBe(true);
  });
});
