export type ToolName = 'trivy' | 'semgrep' | 'gitleaks';

export type ToolStatus = 'waiting' | 'running' | 'done' | 'issues_found' | 'failed';

export type Severity = 'high' | 'medium' | 'low';

export interface SeverityCounts {
  high: number;
  medium: number;
  low: number;
}

export interface ToolResult {
  tool: ToolName;
  status: ToolStatus;
  durationSec: number;
  counts: SeverityCounts;
  error?: string;
}

export interface Finding {
  tool: ToolName;
  rule: string;
  severity: Severity;
  location: string;
  line?: number;
  message: string;
}

export interface ScanSummary {
  tools: ToolResult[];
  totalCounts: SeverityCounts;
  totalDurationSec: number;
  savedPath: string;
}

export interface ScanOptions {
  failTool?: ToolName;
  speedMultiplier?: number;
  abortSignal?: AbortSignal;
}

export interface ToolUpdate {
  tool: ToolName;
  status: ToolStatus;
  elapsedSec: number;
  error?: string;
  counts?: SeverityCounts;
}

export type ScanUpdateCallback = (update: ToolUpdate) => void;
