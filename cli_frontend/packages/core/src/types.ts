export type ToolName = "trivy" | "semgrep" | "gitleaks";

export type ToolStatus =
  "waiting" | "running" | "done" | "issues_found" | "failed";

export type Severity = "high" | "medium" | "low";

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
  targetPath?: string;
  sarifFiles?: Record<ToolName, string>;
}

export interface ToolUpdate {
  tool: ToolName;
  status: ToolStatus;
  elapsedSec: number;
  error?: string;
  counts?: SeverityCounts;
}

export type ScanUpdateCallback = (update: ToolUpdate) => void;

// --- SARIF 2.1.0 Schema Types for Ingestion ---

export interface SarifPhysicalLocation {
  artifactLocation?: {
    uri?: string;
    uriBaseId?: string;
    index?: number;
  };
  region?: {
    startLine?: number;
    startColumn?: number;
    endLine?: number;
    endColumn?: number;
    snippet?: {
      text?: string;
    };
  };
}

export interface SarifLocation {
  physicalLocation?: SarifPhysicalLocation;
  message?: {
    text?: string;
  };
}

export interface SarifRule {
  id: string;
  name?: string;
  shortDescription?: { text?: string };
  fullDescription?: { text?: string };
  defaultConfiguration?: {
    level?: "error" | "warning" | "note" | "none";
  };
  properties?: {
    "security-severity"?: string | number;
    tags?: string[];
    precision?: string;
    problem?: {
      severity?: string;
    };
    [key: string]: unknown;
  };
}

export interface SarifResult {
  ruleId?: string;
  ruleIndex?: number;
  level?: "error" | "warning" | "note" | "none";
  message?: {
    text?: string;
  };
  locations?: SarifLocation[];
  fingerprints?: Record<string, string>;
  partialFingerprints?: Record<string, string>;
  properties?: {
    "security-severity"?: string | number;
    [key: string]: unknown;
  };
}

export interface SarifDriver {
  name: string;
  version?: string;
  semanticVersion?: string;
  informationUri?: string;
  rules?: SarifRule[];
}

export interface SarifInvocation {
  executionSuccessful?: boolean;
  exitCode?: number;
  startTimeUtc?: string;
  endTimeUtc?: string;
  workingDirectory?: {
    uri?: string;
  };
}

export interface SarifRun {
  tool: {
    driver: SarifDriver;
  };
  results?: SarifResult[];
  invocations?: SarifInvocation[];
}

export interface SarifLog {
  version: string;
  $schema?: string;
  runs: SarifRun[];
}

// --- Tool Runner Types for Tool Integration ---

export interface ToolRunOptions {
  targetPath: string;
  outputPath: string;
  timeoutMs?: number;
  abortSignal?: AbortSignal;
}

export interface ToolRunOutput {
  tool: ToolName;
  status: ToolStatus;
  exitCode: number;
  durationSec: number;
  sarifPath?: string;
  sarifLog?: SarifLog;
  counts: SeverityCounts;
  error?: string;
}

export interface ToolRunner {
  readonly name: ToolName;
  isAvailable(): Promise<boolean>;
  buildArgs(targetPath: string, outputPath: string): string[];
  run(options: ToolRunOptions): Promise<ToolRunOutput>;
}
