import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
  validateSarif,
  validateSarifDetailed,
  assertValidSarif,
  SarifValidationError,
} from "../src/sarif/validator.js";
import type { SarifLog } from "../src/types.js";

describe("SARIF Official Schema Validator (validator.ts)", () => {
  const minimalValidSarif: SarifLog = {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "trivy",
            version: "0.58.0",
          },
        },
        results: [],
      },
    ],
  };

  const fullValidSarif: SarifLog = {
    $schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "gitleaks",
            semanticVersion: "8.18.0",
            rules: [
              {
                id: "generic-api-key",
                shortDescription: { text: "Generic API Key detected" },
                defaultConfiguration: { level: "error" },
                properties: { "security-severity": "8.5" },
              },
            ],
          },
        },
        results: [
          {
            ruleId: "generic-api-key",
            level: "error",
            message: { text: "Found unencrypted API key" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "config/secrets.env" },
                  region: { startLine: 12 },
                },
              },
            ],
          },
        ],
      },
    ],
  };

  it("accepts a minimal valid SARIF 2.1.0 document", () => {
    expect(validateSarif(minimalValidSarif)).toBe(true);
    const detailed = validateSarifDetailed(minimalValidSarif);
    expect(detailed.valid).toBe(true);
    expect(detailed.errors).toEqual([]);
    expect(() => assertValidSarif(minimalValidSarif)).not.toThrow();
  });

  it("accepts a full valid SARIF 2.1.0 document with rules, findings, and locations", () => {
    expect(validateSarif(fullValidSarif)).toBe(true);
    const detailed = validateSarifDetailed(fullValidSarif);
    expect(detailed.valid).toBe(true);
    expect(detailed.errors).toHaveLength(0);
    expect(() => assertValidSarif(fullValidSarif)).not.toThrow();
  });

  it("rejects non-object and null values", () => {
    expect(validateSarif(null)).toBe(false);
    expect(validateSarif(undefined)).toBe(false);
    expect(validateSarif("not an object")).toBe(false);
    expect(validateSarif(12345)).toBe(false);
    expect(validateSarif([])).toBe(false);

    const detailed = validateSarifDetailed(null);
    expect(detailed.valid).toBe(false);
    expect(detailed.errors[0].keyword).toBe("type");
  });

  it("rejects incorrect SARIF versions", () => {
    const v1 = { version: "1.0.0", runs: [] };
    const v20 = { version: "2.0.0", runs: [] };
    const missingV = { runs: [] };

    expect(validateSarif(v1)).toBe(false);
    expect(validateSarif(v20)).toBe(false);
    expect(validateSarif(missingV)).toBe(false);

    const detailedV1 = validateSarifDetailed(v1);
    expect(detailedV1.valid).toBe(false);
    expect(detailedV1.errors.some((e) => e.path === "/version")).toBe(true);
  });

  it("rejects documents missing required 'runs' array", () => {
    const missingRuns = { version: "2.1.0" };
    expect(validateSarif(missingRuns)).toBe(false);

    const detailed = validateSarifDetailed(missingRuns);
    expect(detailed.valid).toBe(false);
    expect(detailed.errors.some((e) => e.keyword === "required" && e.params?.missingProperty === "runs")).toBe(true);
  });

  it("rejects invalid property types (e.g. runs is not an array, version is a number)", () => {
    const runsObject = { version: "2.1.0", runs: {} };
    const runsString = { version: "2.1.0", runs: "invalid" };
    const numericVersion = { version: 2.1, runs: [] };

    expect(validateSarif(runsObject)).toBe(false);
    expect(validateSarif(runsString)).toBe(false);
    expect(validateSarif(numericVersion)).toBe(false);
  });

  it("rejects runs missing required tool or driver", () => {
    const missingTool = {
      version: "2.1.0",
      runs: [{ results: [] }],
    };
    const missingDriver = {
      version: "2.1.0",
      runs: [{ tool: {} }],
    };
    const missingDriverName = {
      version: "2.1.0",
      runs: [{ tool: { driver: {} } }],
    };

    expect(validateSarif(missingTool)).toBe(false);
    expect(validateSarif(missingDriver)).toBe(false);
    expect(validateSarif(missingDriverName)).toBe(false);
  });

  it("rejects runs with invalid results array", () => {
    const resultsNotArray = {
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "trivy" } },
          results: "not-an-array",
        },
      ],
    };
    expect(validateSarif(resultsNotArray)).toBe(false);
  });

  it("assertValidSarif throws SarifValidationError with actionable details", () => {
    const invalidDoc = {
      version: "3.0.0",
      runs: [{ tool: { driver: {} } }],
    };

    expect(() => assertValidSarif(invalidDoc)).toThrow(SarifValidationError);
    try {
      assertValidSarif(invalidDoc);
    } catch (err) {
      expect(err).toBeInstanceOf(SarifValidationError);
      const validationErr = err as SarifValidationError;
      expect(validationErr.errors.length).toBeGreaterThan(0);
      expect(validationErr.message).toContain("SARIF validation failed");
    }
  });

  it("validates real-world Trivy SARIF report against full official schema", () => {
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const trivyFixturePath = path.resolve(__dirname, "./fixtures/trivy-sample.sarif");
    const raw = fs.readFileSync(trivyFixturePath, "utf-8");
    const parsed = JSON.parse(raw);

    const result = validateSarifDetailed(parsed);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(validateSarif(parsed)).toBe(true);
  });

  it("validates real-world Gitleaks SARIF report against full official schema", () => {
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const gitleaksFixturePath = path.resolve(__dirname, "./fixtures/gitleaks-sample.sarif");
    const raw = fs.readFileSync(gitleaksFixturePath, "utf-8");
    const parsed = JSON.parse(raw);

    const result = validateSarifDetailed(parsed);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(validateSarif(parsed)).toBe(true);
  });
});

