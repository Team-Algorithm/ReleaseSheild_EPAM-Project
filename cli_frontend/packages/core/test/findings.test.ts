import { describe, it, expect } from "vitest";
import {
  filterFindings,
  sortFindings,
  paginateFindings,
  getSeverityWeight,
  EMPTY_FINDINGS,
} from "../src/findings.js";
import type { Finding } from "../src/types.js";

describe("Findings Processing & Utilities", () => {
  const sampleFindings: Finding[] = [
    {
      tool: "semgrep",
      rule: "rule.sql-injection",
      severity: "high",
      location: "src/api.ts",
      line: 10,
      message: "SQL injection",
    },
    {
      tool: "trivy",
      rule: "CVE-2023-1111",
      severity: "medium",
      location: "package.json",
      line: 25,
      message: "Vulnerable package",
    },
    {
      tool: "gitleaks",
      rule: "api-token",
      severity: "low",
      location: ".env.example",
      line: 5,
      message: "Token pattern",
    },
  ];

  it("provides empty immutable default findings array", () => {
    expect(EMPTY_FINDINGS).toEqual([]);
    expect(Array.isArray(EMPTY_FINDINGS)).toBe(true);
  });

  it("filters findings by severity", () => {
    const high = filterFindings(sampleFindings, { severity: "high" });
    expect(high.length).toBe(1);
    expect(high[0].rule).toBe("rule.sql-injection");
  });

  it("filters findings by tool", () => {
    const trivy = filterFindings(sampleFindings, { tool: "trivy" });
    expect(trivy.length).toBe(1);
    expect(trivy[0].tool).toBe("trivy");
  });

  it("filters findings by search query", () => {
    const searched = filterFindings(sampleFindings, { search: "api.ts" });
    expect(searched.length).toBe(1);
    expect(searched[0].location).toBe("src/api.ts");
  });

  it("sorts findings by severity (high to low by default)", () => {
    const sorted = sortFindings([...sampleFindings]);
    expect(sorted[0].severity).toBe("high");
    expect(sorted[1].severity).toBe("medium");
    expect(sorted[2].severity).toBe("low");
  });

  it("sorts findings by tool name", () => {
    const sorted = sortFindings([...sampleFindings], "tool");
    expect(sorted[0].tool).toBe("gitleaks");
    expect(sorted[1].tool).toBe("semgrep");
    expect(sorted[2].tool).toBe("trivy");
  });

  it("paginates findings properly", () => {
    const page1 = paginateFindings(sampleFindings, 1, 2);
    expect(page1.currentPage).toBe(1);
    expect(page1.totalPages).toBe(2);
    expect(page1.findings.length).toBe(2);

    const page2 = paginateFindings(sampleFindings, 2, 2);
    expect(page2.currentPage).toBe(2);
    expect(page2.findings.length).toBe(1);
  });

  it("calculates severity weights accurately", () => {
    expect(getSeverityWeight("high")).toBe(3);
    expect(getSeverityWeight("medium")).toBe(2);
    expect(getSeverityWeight("low")).toBe(1);
  });
});
