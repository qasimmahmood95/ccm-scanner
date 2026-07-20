import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { allChecks } from "../../src/controls/index.js";
import { createRegistry, domainOfCcmId, type CcmDomain } from "../../src/index.js";

/**
 * ADR-0003 makes `docs/control-mapping.md` the source of truth and commits us to
 * enforcing that with a test rather than with discipline. This is that test.
 *
 * Without it the ADR is a promise: code and table drift, and a report cites a
 * control id or title that no longer means what the table says it means.
 */

/** Domains whose checks are implemented. Extend as each milestone lands. */
const IMPLEMENTED_DOMAINS: readonly CcmDomain[] = ["IAM", "CEK"];

interface MappingRow {
  readonly ccmId: string;
  readonly ccmTitle: string;
  readonly checkId: string | undefined;
}

function parseMappingTable(markdown: string): readonly MappingRow[] {
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
    });
  }
  return rows;
}

const mapping = parseMappingTable(
  readFileSync(new URL("../../docs/control-mapping.md", import.meta.url), "utf8"),
);

describe("the mapping table itself", () => {
  it("parses into rows", () => {
    expect(mapping.length).toBeGreaterThan(20);
  });

  it("gives every row a well-formed CCM id", () => {
    for (const row of mapping) {
      expect(row.ccmId, `row "${row.ccmTitle}"`).toMatch(/^(IAM|LOG|CEK|IVS)-\d{2}$/);
    }
  });

  it("declares each check id at most once", () => {
    const ids = mapping.flatMap((row) => (row.checkId === undefined ? [] : [row.checkId]));
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe("registered checks match the mapping table", () => {
  it("registers cleanly", () => {
    expect(() => createRegistry(allChecks)).not.toThrow();
  });

  it("has a mapping row for every registered check", () => {
    for (const check of allChecks) {
      const row = mapping.find((candidate) => candidate.checkId === check.checkId);
      expect(row, `no row in control-mapping.md for check "${check.checkId}"`).toBeDefined();
    }
  });

  it("agrees with the table on every control id", () => {
    for (const check of allChecks) {
      const row = mapping.find((candidate) => candidate.checkId === check.checkId);
      expect(row?.ccmId, `ccmId for "${check.checkId}"`).toBe(check.ccmId);
    }
  });

  // Titles are quoted verbatim from CCM; a paraphrase in either place is drift.
  it("agrees with the table on every control title, byte for byte", () => {
    for (const check of allChecks) {
      const row = mapping.find((candidate) => candidate.checkId === check.checkId);
      expect(row?.ccmTitle, `ccmTitle for "${check.checkId}"`).toBe(check.ccmTitle);
    }
  });

  it("implements every check the table declares for an implemented domain", () => {
    const registered = new Set(allChecks.map((check) => check.checkId));
    for (const row of mapping) {
      const domain = domainOfCcmId(row.ccmId);
      if (row.checkId === undefined || domain === undefined) {
        continue;
      }
      if (IMPLEMENTED_DOMAINS.includes(domain)) {
        expect(
          registered.has(row.checkId),
          `table declares "${row.checkId}" but no check does`,
        ).toBe(true);
      }
    }
  });

  it("registers no check for a domain that is not yet implemented", () => {
    for (const check of allChecks) {
      const domain = domainOfCcmId(check.ccmId);
      expect(domain === undefined || IMPLEMENTED_DOMAINS.includes(domain)).toBe(true);
    }
  });
});
