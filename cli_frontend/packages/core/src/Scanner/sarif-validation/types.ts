export interface SarifLog {
  $schema?: string;
  version: string;
  runs: SarifRun[];
  [key: string]: unknown;
}

export interface SarifRun {
  [key: string]: unknown;
}
