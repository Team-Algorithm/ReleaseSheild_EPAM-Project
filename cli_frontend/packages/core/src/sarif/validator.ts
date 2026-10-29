import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import AjvDraft04 from "ajv-draft-04";
import addFormats from "ajv-formats";
import type { AnyValidateFunction } from "ajv/dist/core.js";
import type { SarifLog } from "../types.js";

export interface SarifValidationErrorDetail {
  path: string;
  message: string;
  keyword: string;
  params?: Record<string, unknown>;
}

export interface SarifValidationResult {
  valid: boolean;
  errors: SarifValidationErrorDetail[];
}

export class SarifValidationError extends Error {
  readonly errors: SarifValidationErrorDetail[];

  constructor(message: string, errors: SarifValidationErrorDetail[] = []) {
    super(message);
    this.name = "SarifValidationError";
    this.errors = errors;
  }
}

/**
 * Robustly resolves the path to the official SARIF 2.1.0 JSON Schema on disk
 * across development (source), compilation (dist), test (vitest), and CLI runtime environments.
 */
function resolveSchemaPath(): string {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    // Relative to src/sarif or dist/sarif
    path.resolve(currentDir, "../../schemas/sarif-schema-2.1.0.json"),
    path.resolve(currentDir, "../schemas/sarif-schema-2.1.0.json"),
    // Relative to current working directory (e.g. cli_frontend or workspace root)
    path.resolve(process.cwd(), "packages/core/schemas/sarif-schema-2.1.0.json"),
    path.resolve(process.cwd(), "cli_frontend/packages/core/schemas/sarif-schema-2.1.0.json"),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  throw new Error(
    `SARIF 2.1.0 JSON Schema not found on disk. Looked in: ${candidates.join(", ")}`
  );
}

let compiledValidator: AnyValidateFunction<SarifLog> | null = null;

/**
 * Initializes and caches the compiled Ajv Draft-04 validator against the official SARIF schema.
 */
function getValidator(): AnyValidateFunction<SarifLog> {
  if (compiledValidator) {
    return compiledValidator;
  }

  const schemaPath = resolveSchemaPath();
  const schemaContent = fs.readFileSync(schemaPath, "utf-8");
  let schema: Record<string, unknown>;
  try {
    schema = JSON.parse(schemaContent);
  } catch (err) {
    throw new Error(
      `Failed to parse local SARIF schema JSON at ${schemaPath}: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  const AjvClass = typeof AjvDraft04 === "function" ? AjvDraft04 : (AjvDraft04 as any).default;
  const formatPlugin = typeof addFormats === "function" ? addFormats : (addFormats as any).default;

  const ajv = new AjvClass({
    allErrors: true,
    strict: false, // Required for Draft-04 errata references in official OASIS schema
  });
  formatPlugin(ajv);

  compiledValidator = ajv.compile(schema) as AnyValidateFunction<SarifLog>;
  return compiledValidator;
}

/**
 * Performs full official OASIS SARIF 2.1.0 JSON Schema validation on an unknown document.
 * Returns detailed validation information without throwing.
 */
export function validateSarifDetailed(sarif: unknown): SarifValidationResult {
  if (typeof sarif !== "object" || sarif === null) {
    return {
      valid: false,
      errors: [
        {
          path: "",
          message: "SARIF document must be a non-null object",
          keyword: "type",
        },
      ],
    };
  }

  const validator = getValidator();
  const isValid = Boolean(validator(sarif));

  if (isValid) {
    return { valid: true, errors: [] };
  }

  const errors: SarifValidationErrorDetail[] = (validator.errors || []).map((err) => ({
    path: err.instancePath || "/",
    message: err.message || "Schema constraint violation",
    keyword: err.keyword,
    params: err.params as Record<string, unknown>,
  }));

  return { valid: false, errors };
}

/**
 * TypeScript type guard validating that an object conforms to official SARIF 2.1.0 specifications.
 * Preserves the existing signature and behavior while checking the full OASIS schema.
 */
export function validateSarif(sarif: unknown): sarif is SarifLog {
  return validateSarifDetailed(sarif).valid;
}

/**
 * Asserts that an unknown object is valid SARIF 2.1.0, throwing a descriptive SarifValidationError if not.
 */
export function assertValidSarif(sarif: unknown): asserts sarif is SarifLog {
  const result = validateSarifDetailed(sarif);
  if (!result.valid) {
    const errorDetails = result.errors
      .slice(0, 5)
      .map((e) => `${e.path ? e.path + ": " : ""}${e.message}`)
      .join("; ");
    throw new SarifValidationError(
      `SARIF validation failed: ${errorDetails}${result.errors.length > 5 ? ` (+${result.errors.length - 5} more errors)` : ""}`,
      result.errors
    );
  }
}

