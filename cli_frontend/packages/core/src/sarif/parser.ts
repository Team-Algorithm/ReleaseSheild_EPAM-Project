import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { SarifLog } from "../types.js";
import { assertValidSarif, validateSarifDetailed, SarifValidationError } from "./validator.js";

/**
 * Parses a raw JSON string into a validated SarifLog structure.
 * Distinguishes JSON syntax errors from schema-validation errors.
 */
export function parseSarif(jsonString: string): SarifLog {
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonString);
  } catch (err) {
    throw new Error(
      `Failed to parse SARIF JSON: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  // Validate against official OASIS SARIF 2.1.0 schema
  const validation = validateSarifDetailed(parsed);
  if (!validation.valid) {
    const errorDetails = validation.errors
      .slice(0, 5)
      .map((e) => `${e.path ? e.path + ": " : ""}${e.message}`)
      .join("; ");
    throw new SarifValidationError(
      `Invalid SARIF 2.1.0 structure: ${errorDetails}${validation.errors.length > 5 ? ` (+${validation.errors.length - 5} more errors)` : ""}`,
      validation.errors
    );
  }

  return parsed as SarifLog;
}

/**
 * Reads and validates a SARIF file from the filesystem.
 * Preserves filesystem errors (e.g. ENOENT, EACCES) directly.
 */
export async function readSarifFile(filePath: string): Promise<SarifLog> {
  const content = await fs.readFile(filePath, "utf-8");
  return parseSarif(content);
}

/**
 * Safely and atomically writes a SARIF document to the filesystem.
 *
 * Publication procedure:
 * 1. Creates any missing parent directories recursively.
 * 2. Validates the SARIF document against the official schema before touching disk.
 * 3. Writes formatted JSON to a unique temporary file in the destination directory.
 * 4. Atomically renames the temporary file to the final destination.
 * 5. Cleans up temporary artifacts if writing or renaming fails.
 */
export async function writeSarifFile(
  filePath: string,
  sarif: SarifLog
): Promise<void> {
  // Validate before writing to avoid publishing corrupt data
  assertValidSarif(sarif);

  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });

  const randomSuffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const tempPath = `${filePath}.${randomSuffix}.sarif.tmp`;
  const jsonContent = JSON.stringify(sarif, null, 2);

  try {
    await fs.writeFile(tempPath, jsonContent, "utf-8");
    await fs.rename(tempPath, filePath);
  } catch (err) {
    // Attempt cleanup of the temporary staging file without masking the original error
    try {
      await fs.unlink(tempPath);
    } catch {
      // Ignore cleanup error if temp file does not exist
    }
    throw err;
  }
}
