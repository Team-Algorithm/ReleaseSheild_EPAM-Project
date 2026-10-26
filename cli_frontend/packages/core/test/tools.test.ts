import { describe, it, expect } from 'vitest';
import { getToolRunner, TrivyRunner, SemgrepRunner, GitleaksRunner } from '../src/tools.js';

describe('Tool Runners Integration Layer', () => {
  it('retrieves runner instances for all supported tools', () => {
    const trivy = getToolRunner('trivy');
    const semgrep = getToolRunner('semgrep');
    const gitleaks = getToolRunner('gitleaks');

    expect(trivy).toBeInstanceOf(TrivyRunner);
    expect(semgrep).toBeInstanceOf(SemgrepRunner);
    expect(gitleaks).toBeInstanceOf(GitleaksRunner);

    expect(trivy.name).toBe('trivy');
    expect(semgrep.name).toBe('semgrep');
    expect(gitleaks.name).toBe('gitleaks');
  });

  it('builds proper CLI arguments for Trivy', () => {
    const runner = new TrivyRunner();
    const args = runner.buildArgs('./my-repo', './out.sarif');
    expect(args).toEqual(['fs', '--format', 'sarif', '--output', './out.sarif', './my-repo']);
  });

  it('builds proper CLI arguments for Semgrep', () => {
    const runner = new SemgrepRunner();
    const args = runner.buildArgs('./my-repo', './out.sarif');
    expect(args).toEqual(['scan', '--sarif', '--output', './out.sarif', './my-repo']);
  });

  it('builds proper CLI arguments for Gitleaks', () => {
    const runner = new GitleaksRunner();
    const args = runner.buildArgs('./my-repo', './out.sarif');
    expect(args).toEqual([
      'detect',
      '--source',
      './my-repo',
      '--report-format',
      'sarif',
      '--report-path',
      './out.sarif'
    ]);
  });
});
