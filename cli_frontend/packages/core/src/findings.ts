import type { Finding, Severity } from "./types.js";

/**
 * Empty findings list - used as default clean state before scans.
 */
export const EMPTY_FINDINGS: readonly Finding[] = Object.freeze([]);

/**
 * Maps severity names to numerical weights for sorting purposes.
 */
export function getSeverityWeight(severity: Severity): number {
  switch (severity) {
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

/**
 * Filter findings by optional criteria (severity, tool name, text query).
 */
export function filterFindings(
  findings: Finding[],
  filters?: {
    severity?: string;
    tool?: string;
    search?: string;
  },
): Finding[] {
  if (!filters) return findings;

  return findings.filter((f) => {
    if (
      filters.severity &&
      f.severity.toLowerCase() !== filters.severity.toLowerCase()
    ) {
      return false;
    }
    if (filters.tool && f.tool.toLowerCase() !== filters.tool.toLowerCase()) {
      return false;
    }
    if (filters.search) {
      const q = filters.search.toLowerCase();
      const match =
        f.rule.toLowerCase().includes(q) ||
        f.location.toLowerCase().includes(q) ||
        f.message.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });
}

/**
 * Sorts findings by severity (high to low by default), tool, or location.
 */
export function sortFindings(
  findings: Finding[],
  sortBy: "severity" | "tool" | "location" = "severity",
): Finding[] {
  return [...findings].sort((a, b) => {
    if (sortBy === "severity") {
      const diff =
        getSeverityWeight(b.severity) - getSeverityWeight(a.severity);
      if (diff !== 0) return diff;
      return a.location.localeCompare(b.location);
    }
    if (sortBy === "tool") {
      const diff = a.tool.localeCompare(b.tool);
      if (diff !== 0) return diff;
      return getSeverityWeight(b.severity) - getSeverityWeight(a.severity);
    }
    if (sortBy === "location") {
      const diff = a.location.localeCompare(b.location);
      if (diff !== 0) return diff;
      return (a.line ?? 0) - (b.line ?? 0);
    }
    return 0;
  });
}

/**
 * Paginates a list of findings.
 */
export function paginateFindings(
  findings: Finding[],
  page = 1,
  pageSize = 10,
): {
  findings: Finding[];
  totalPages: number;
  currentPage: number;
  totalFindings: number;
} {
  const totalFindings = findings.length;
  const totalPages = Math.max(1, Math.ceil(totalFindings / pageSize));
  const currentPage = Math.min(Math.max(1, page), totalPages);
  const startIndex = (currentPage - 1) * pageSize;
  const pageFindings = findings.slice(startIndex, startIndex + pageSize);

  return {
    findings: pageFindings,
    totalPages,
    currentPage,
    totalFindings,
  };
}
