import fs from "node:fs";
import path from "node:path";
import AjvDraft04 from "ajv-draft-04";
import addFormatsPlugin from "ajv-formats";
import type { SarifLog } from "./types.js";

export class SarifValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SarifValidationError";
  }
}

const DEFAULT_SCHEMA_PATH = path.resolve(
  process.cwd(),
  "schemas",
  "sarif-schema-2.1.0.json",
);

function readJson(filePath: string): unknown {
  if (!fs.existsSync(filePath)) {
    throw new SarifValidationError(`File does not exist: ${filePath}`);
  }
  let stats: fs.Stats;
  try {
    stats = fs.statSync(filePath);
  } catch {
    throw new SarifValidationError(`Cannot access file: ${filePath}`);
  }
  if (!stats.isFile()) {
    throw new SarifValidationError(`Path is not a file: ${filePath}`);
  }

  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch {
    throw new SarifValidationError(`File is not readable: ${filePath}`);
  }
  try {
    return JSON.parse(raw) as unknown;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new SarifValidationError(`Malformed JSON in ${filePath}: ${detail}`);
  }
}

/** Read and validate a SARIF 2.1.0 report against the repository schema. */
export function validateSarif(
  filePath: string,
  schemaPath = DEFAULT_SCHEMA_PATH,
): SarifLog {
  const schema = readJson(schemaPath);
  const report = readJson(filePath);

  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new SarifValidationError("SARIF root must be a JSON object.");
  }

  const candidate = report as Record<string, unknown>;
  if (candidate.version !== "2.1.0") {
    throw new SarifValidationError(
      `Unsupported SARIF version: ${String(candidate.version)}. Expected 2.1.0.`,
    );
  }
  if (!Array.isArray(candidate.runs)) {
    throw new SarifValidationError('Invalid SARIF: "runs" must be an array.');
  }

  const Ajv = AjvDraft04 as unknown as new (options?: Record<string, unknown>) => import("ajv").default;
  const ajv = new Ajv({ allErrors: true, strict: false });
  const addFormats = addFormatsPlugin as unknown as (instance: typeof ajv) => void;
  addFormats(ajv);
  let validate: ReturnType<typeof ajv.compile>;
  try {
    validate = ajv.compile(schema as any);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new SarifValidationError(`Could not load SARIF schema: ${detail}`);
  }

  if (!validate(candidate)) {
    const details = (validate.errors ?? [])
      .map((e: { instancePath: string; message?: string }) => `${e.instancePath || "/"} ${e.message ?? "is invalid"}`)
      .join("; ");
    throw new SarifValidationError(`SARIF schema validation failed: ${details}`);
  }
  return candidate as unknown as SarifLog;
}
