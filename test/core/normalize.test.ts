import { describe, it, expect } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  normalizeAndSaveSarif,
  normalizeAndSaveSarifSync,
  normalizeScanner,
  normalizeSarif,
  normalizeSarifFile,
  normalizeSarifFileSync,
  normalizeTitle,
  toRepoRelativePath,
  type NormalizableSarifLog,
} from "../../packages/core/src/Normalization/normalize.js";

const SAMPLE_RESULT_SARIF: NormalizableSarifLog = {
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "Trivy",
          fullName: "Trivy Vulnerability Scanner",
          rules: [],
        },
      },
      results: [],
      originalUriBaseIds: {
        ROOTPATH: {
          uri: "file:///C:/Users/HP/Desktop/emosense-companion/",
        },
      },
    },
    {
      tool: {
        driver: {
          name: "Semgrep OSS",
          rules: [
            {
              id: "generic.secrets.security.detected-jwt-token.detected-jwt-token",
              name: "generic.secrets.security.detected-jwt-token.detected-jwt-token",
              defaultConfiguration: { level: "error" },
              shortDescription: {
                text: "Semgrep Finding: generic.secrets.security.detected-jwt-token.detected-jwt-token",
              },
              properties: {
                tags: ["CWE-321", "security"],
              },
            },
            {
              id: "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag",
              defaultConfiguration: { level: "warning" },
              shortDescription: {
                text: "Semgrep Finding: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag",
              },
            },
          ],
        },
      },
      results: [
        {
          ruleId:
            "generic.secrets.security.detected-jwt-token.detected-jwt-token",
          fingerprints: { "matchBasedId/v1": "requires login" },
          message: { text: "JWT token detected" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: "C:\\Users\\HP\\Desktop\\emosense-companion\\.env",
                },
                region: {
                  startLine: 2,
                  endLine: 2,
                  startColumn: 32,
                  endColumn: 197,
                  snippet: {
                    text: 'VITE_SUPABASE_PUBLISHABLE_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sample"',
                  },
                },
              },
            },
          ],
        },
        {
          ruleId:
            "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag",
          message: {
            text: "GitHub Actions step uses a mutable tag or branch reference.",
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: "C:\\Users\\HP\\Desktop\\emosense-companion\\.github\\workflows\\quality.yml",
                },
                region: {
                  startLine: 16,
                  endLine: 16,
                  startColumn: 9,
                  endColumn: 34,
                  snippet: { text: "      - uses: actions/checkout@v4" },
                },
              },
            },
          ],
        },
      ],
    },
    {
      tool: {
        driver: {
          name: "gitleaks",
          rules: [
            {
              id: "jwt",
              shortDescription: {
                text: "Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data.",
              },
            },
          ],
        },
      },
      results: [
        {
          ruleId: "jwt",
          partialFingerprints: { commitSha: "" },
          message: {
            text: "jwt has detected secret for file C:/Users/HP/Desktop/emosense-companion/.env.",
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: "C:/Users/HP/Desktop/emosense-companion/.env",
                },
                region: {
                  startLine: 2,
                  endLine: 2,
                  startColumn: 33,
                  endColumn: 241,
                  snippet: {
                    text: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sample",
                  },
                },
              },
            },
          ],
        },
      ],
    },
  ],
};

describe("SARIF Normalization (PostgreSQL Sprint 2 Schema)", () => {
  it("normalizes scanner driver names to DB enum values", () => {
    expect(normalizeScanner("Semgrep OSS")).toBe("semgrep");
    expect(normalizeScanner("Trivy")).toBe("trivy");
    expect(normalizeScanner("gitleaks")).toBe("gitleaks");
    expect(() => normalizeScanner("unknown-tool")).toThrow(
      /Unsupported scanner driver/
    );
  });

  it("normalizes titles and strips repo root for repository-relative CODEOWNERS paths", () => {
    expect(
      normalizeTitle(
        "Semgrep Finding: generic.secrets.security.detected-jwt-token.detected-jwt-token"
      )
    ).toBe(
      "semgrep-finding-generic-secrets-security-detected-jwt-token-detected-jwt-token"
    );

    expect(
      toRepoRelativePath(
        "C:\\Users\\HP\\Desktop\\emosense-companion\\.github\\workflows\\quality.yml",
        ["C:/Users/HP/Desktop/emosense-companion"],
        "emosense-companion"
      )
    ).toBe(".github/workflows/quality.yml");
  });

  it("normalizes multi-run result.sarif into DB-aligned issues and issue_occurrences fields", () => {
    const findings = normalizeSarif(SAMPLE_RESULT_SARIF);

    expect(findings).toHaveLength(3);
    expect(findings[0]).toEqual({
      repoId: "emosense-companion",
      scanner: "semgrep",
      ruleId:
        "generic.secrets.security.detected-jwt-token.detected-jwt-token",
      title:
        "Semgrep Finding: generic.secrets.security.detected-jwt-token.detected-jwt-token",
      normalizedTitle:
        "semgrep-finding-generic-secrets-security-detected-jwt-token-detected-jwt-token",
      severity: "high",
      filePath: ".env",
      startLine: 2,
      endLine: 2,
      startColumn: 32,
      endColumn: 197,
      codeFingerprint: null,
      evidence: {
        message: "JWT token detected",
        snippet:
          'VITE_SUPABASE_PUBLISHABLE_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sample"',
        driverName: "Semgrep OSS",
        normalizedTitle:
          "semgrep-finding-generic-secrets-security-detected-jwt-token-detected-jwt-token",
        tags: ["CWE-321", "security"],
        fingerprints: { "matchBasedId/v1": "requires login" },
      },
    });

    expect(findings[1]).toMatchObject({
      repoId: "emosense-companion",
      scanner: "semgrep",
      severity: "medium",
      filePath: ".github/workflows/quality.yml",
      startLine: 16,
      endLine: 16,
      startColumn: 9,
      endColumn: 34,
    });

    expect(findings[2]).toMatchObject({
      repoId: "emosense-companion",
      scanner: "gitleaks",
      ruleId: "jwt",
      severity: "high",
      filePath: ".env",
      startLine: 2,
      endLine: 2,
      startColumn: 33,
      endColumn: 241,
      codeFingerprint: null,
    });
  });

  it("enforces positive integer line/column constraints and maps CVSS/unknown severities", () => {
    const sarif: NormalizableSarifLog = {
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Trivy",
              rules: [
                {
                  id: "CVE-2024-9999",
                  properties: { "security-severity": "9.8" },
                },
                {
                  id: "TRIVY-UNKNOWN",
                },
              ],
            },
          },
          results: [
            {
              ruleId: "CVE-2024-9999",
              message: { text: "Critical vulnerability" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "package.json" },
                    region: { startLine: 0, endLine: -1, startColumn: 0 },
                  },
                },
              ],
            },
            {
              ruleId: "TRIVY-UNKNOWN",
              message: { text: "Unclassified issue" },
              partialFingerprints: { primaryLocationLineHash: "abc123hash" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "./Dockerfile" },
                  },
                },
              ],
            },
          ],
        },
      ],
    };

    const findings = normalizeSarif(sarif, { repoId: "NodeGoat" });
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].startLine).toBeNull();
    expect(findings[0].endLine).toBeNull();
    expect(findings[0].startColumn).toBeNull();
    expect(findings[1].severity).toBe("unknown");
    expect(findings[1].filePath).toBe("Dockerfile");
    expect(findings[1].codeFingerprint).toBe("abc123hash");
  });

  it("reads and normalizes a result.sarif file from disk (sync and async)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sarif-norm-"));
    const sarifPath = join(dir, "result.sarif");

    try {
      writeFileSync(sarifPath, JSON.stringify(SAMPLE_RESULT_SARIF), "utf8");
      const syncFindings = normalizeSarifFileSync(sarifPath);
      const asyncFindings = await normalizeSarifFile(sarifPath);
      expect(syncFindings).toHaveLength(3);
      expect(asyncFindings).toEqual(syncFindings);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("writes normalized-findings.json from result.sarif (sync and async)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sarif-norm-out-"));
    const sarifPath = join(dir, "result.sarif");
    const syncOutPath = join(dir, "normalized-sync.json");
    const asyncOutPath = join(dir, "normalized-async.json");

    try {
      writeFileSync(sarifPath, JSON.stringify(SAMPLE_RESULT_SARIF), "utf8");

      const syncRes = normalizeAndSaveSarifSync(sarifPath, syncOutPath);
      const asyncRes = await normalizeAndSaveSarif(sarifPath, asyncOutPath);

      expect(existsSync(syncOutPath)).toBe(true);
      expect(existsSync(asyncOutPath)).toBe(true);
      expect(syncRes.findings).toHaveLength(3);
      expect(asyncRes.findings).toEqual(syncRes.findings);
      expect(JSON.parse(readFileSync(asyncOutPath, "utf8"))).toEqual(
        syncRes.findings
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("throws on invalid SARIF payload without runs", () => {
    expect(() => normalizeSarif({} as NormalizableSarifLog)).toThrow(
      /Invalid SARIF payload/
    );
  });
});
