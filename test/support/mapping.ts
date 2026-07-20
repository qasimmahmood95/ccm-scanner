import { readFileSync } from "node:fs";
import type { CcmDomain } from "../../src/index.js";

/**
 * Reads `docs/control-mapping.md`, which ADR-0003 makes the source of truth.
 * Shared so the parity test and the fixture-coverage test cannot disagree about
 * what the table says.
 */

/** Domains whose checks are implemented. Extend as each milestone lands. */
export const IMPLEMENTED_DOMAINS: readonly CcmDomain[] = ["IAM", "CEK"];

export interface MappingRow {
  readonly ccmId: string;
  readonly ccmTitle: string;
  readonly checkId: string | undefined;
  /** `Yes`, `Partial` or `NA`. */
  readonly coverage: string;
}

export function parseMappingTable(markdown: string): readonly MappingRow[] {
  const rows: MappingRow[] = [];
  for (const line of markdown.split("\n")) {
    // Control rows are the only ones whose first cell is bold.
    if (!line.startsWith("| **")) {
      continue;
    }
    const cells = line
      .split("|")
      .slice(1, -1)
      .map((cell) => cell.trim());
    const [idCell, titleCell, checkCell] = cells;
    if (idCell === undefined || titleCell === undefined || checkCell === undefined) {
      continue;
    }
    rows.push({
      ccmId: idCell.replaceAll("*", "").trim(),
      // Strip the disambiguating suffix on rows that split one control across
      // two checks, e.g. "Data Encryption *(in transit)*".
      ccmTitle: titleCell.replace(/\s*\*\([^)]*\)\*\s*$/, "").trim(),
      checkId: /`([^`]+)`/.exec(checkCell)?.[1],
      coverage: (cells[cells.length - 1] ?? "").replaceAll("*", "").trim(),
    });
  }
  return rows;
}

export const mapping = parseMappingTable(
  readFileSync(new URL("../../docs/control-mapping.md", import.meta.url), "utf8"),
);

/** Rows whose check is implemented and expected to produce real verdicts. */
export function rowsWithCoverage(coverage: readonly string[]): readonly MappingRow[] {
  return mapping.filter(
    (row) =>
      row.checkId !== undefined &&
      coverage.includes(row.coverage) &&
      IMPLEMENTED_DOMAINS.some((domain) => row.ccmId.startsWith(`${domain}-`)),
  );
}
