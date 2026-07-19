import type { Evidence, Verdict } from "../model/verdict.js";
import type { DomainRollup, Report, StatusCounts } from "./types.js";

/**
 * Serialisation is written out explicitly rather than relying on object key
 * insertion order elsewhere in the codebase. That guarantees byte-identical
 * JSON for a given report, which is what the golden-file tests rest on.
 */

function serialiseEvidence(evidence: Evidence): Record<string, unknown> {
  const out: Record<string, unknown> = { resourceAddress: evidence.resourceAddress };
  if (evidence.attribute !== undefined) {
    out.attribute = evidence.attribute;
  }
  out.observed = evidence.observed === undefined ? null : evidence.observed;
  if (evidence.expected !== undefined) {
    out.expected = evidence.expected;
  }
  return out;
}

function serialiseVerdict(verdict: Verdict): Record<string, unknown> {
  const out: Record<string, unknown> = {
    ccmId: verdict.ccmId,
    ccmTitle: verdict.ccmTitle,
    checkId: verdict.checkId,
    status: verdict.status,
    evidence: verdict.evidence.map(serialiseEvidence),
  };
  if (verdict.reason !== undefined) {
    out.reason = verdict.reason;
  }
  return out;
}

function serialiseCounts(counts: StatusCounts): Record<string, number> {
  return {
    pass: counts.pass,
    fail: counts.fail,
    notApplicable: counts.notApplicable,
    total: counts.total,
  };
}

function serialiseDomain(rollup: DomainRollup): Record<string, unknown> {
  return { domain: rollup.domain, ...serialiseCounts(rollup) };
}

/** The report as a plain JSON-ready object, with canonical key order. */
export function toJsonObject(report: Report): Record<string, unknown> {
  return {
    schemaVersion: report.schemaVersion,
    metadata: {
      tool: {
        name: report.metadata.tool.name,
        version: report.metadata.tool.version,
      },
      ccmVersion: report.metadata.ccmVersion,
      input: {
        source: report.metadata.input.source,
        digest: report.metadata.input.digest,
      },
      generatedAt: report.metadata.generatedAt,
    },
    headline: report.headline,
    totals: serialiseCounts(report.totals),
    domains: report.domains.map(serialiseDomain),
    verdicts: report.verdicts.map(serialiseVerdict),
  };
}

/** Deterministic JSON rendering: canonical key order, 2-space indent, trailing newline. */
export function renderJson(report: Report): string {
  return `${JSON.stringify(toJsonObject(report), null, 2)}\n`;
}
