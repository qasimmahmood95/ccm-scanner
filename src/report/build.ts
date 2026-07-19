import { CCM_DOMAINS, domainOfCcmId } from "../model/ccm.js";
import type { Status, Verdict } from "../model/verdict.js";
import { compareStrings } from "../util/compare.js";
import {
  REPORT_SCHEMA_VERSION,
  type DomainRollup,
  type Headline,
  type Report,
  type RunMetadata,
  type StatusCounts,
} from "./types.js";

const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const TIMESTAMP_PATTERN =
  /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$/;

/**
 * The published schema is only load-bearing if we cannot emit a document that
 * violates it, so metadata is checked here rather than trusted from the caller.
 */
function validateMetadata(metadata: RunMetadata): void {
  const required: readonly [string, string][] = [
    ["tool.name", metadata.tool.name],
    ["tool.version", metadata.tool.version],
    ["ccmVersion", metadata.ccmVersion],
    ["input.source", metadata.input.source],
  ];
  for (const [field, value] of required) {
    if (value.trim() === "") {
      throw new Error(`report metadata ${field} must not be empty`);
    }
  }
  if (!DIGEST_PATTERN.test(metadata.input.digest)) {
    throw new Error(
      `report metadata input.digest must be a 64-character lowercase hex sha256, got ` +
        `"${metadata.input.digest}"`,
    );
  }
  if (!TIMESTAMP_PATTERN.test(metadata.generatedAt)) {
    throw new Error(
      `report metadata generatedAt must be an ISO-8601 timestamp with a timezone, got ` +
        `"${metadata.generatedAt}"`,
    );
  }
  // The pattern only checks shape; "2026-99-99T00:00:00Z" passes it.
  if (Number.isNaN(Date.parse(metadata.generatedAt))) {
    throw new Error(`report metadata generatedAt is not a real date: "${metadata.generatedAt}"`);
  }
}

const STATUSES: readonly Status[] = ["pass", "fail", "not_applicable"];

/**
 * Verdicts are checked here as well as at construction, because this is the
 * last gate before a document is emitted and the published schema is only
 * load-bearing if we cannot produce something that violates it.
 *
 * The domain check matters most: a verdict outside the in-scope domains would
 * be counted in the totals but omitted from every per-domain section — a FAIL
 * that renders as a headline with no detail. Fail loudly instead.
 */
function assertVerdictsAreWellFormed(verdicts: readonly Verdict[]): void {
  for (const verdict of verdicts) {
    if (domainOfCcmId(verdict.ccmId) === undefined) {
      throw new Error(
        `verdict from check "${verdict.checkId}" has ccmId "${verdict.ccmId}", which is not ` +
          `an in-scope CCM control id (expected e.g. "IVS-03"); it would be dropped from the report`,
      );
    }
    if (!STATUSES.includes(verdict.status)) {
      throw new Error(
        `verdict from check "${verdict.checkId}" has unknown status "${String(verdict.status)}"`,
      );
    }
    if (verdict.ccmTitle.trim() === "") {
      throw new Error(`verdict from check "${verdict.checkId}" has an empty ccmTitle`);
    }
    for (const item of verdict.evidence) {
      if (item.resourceAddress.trim() === "") {
        throw new Error(
          `verdict from check "${verdict.checkId}" has evidence with an empty resourceAddress`,
        );
      }
    }
  }
}

function tally(statuses: readonly Status[]): StatusCounts {
  let pass = 0;
  let fail = 0;
  let notApplicable = 0;
  for (const status of statuses) {
    if (status === "pass") {
      pass += 1;
    } else if (status === "fail") {
      fail += 1;
    } else {
      notApplicable += 1;
    }
  }
  return { pass, fail, notApplicable, total: statuses.length };
}

/** A control fails if any finding failed; passes if any passed; else N/A. */
export function statusOfControl(verdicts: readonly Verdict[]): Status {
  if (verdicts.some((verdict) => verdict.status === "fail")) {
    return "fail";
  }
  if (verdicts.some((verdict) => verdict.status === "pass")) {
    return "pass";
  }
  return "not_applicable";
}

/** Groups verdicts by CCM control id, in stable ccmId order. */
export function groupByControl(verdicts: readonly Verdict[]): ReadonlyMap<string, Verdict[]> {
  const groups = new Map<string, Verdict[]>();
  for (const verdict of verdicts) {
    const existing = groups.get(verdict.ccmId);
    if (existing === undefined) {
      groups.set(verdict.ccmId, [verdict]);
    } else {
      existing.push(verdict);
    }
  }
  return new Map([...groups.entries()].sort(([a], [b]) => compareStrings(a, b)));
}

function controlStatuses(verdicts: readonly Verdict[]): readonly Status[] {
  return [...groupByControl(verdicts).values()].map((group) => statusOfControl(group));
}

function rollUpByDomain(verdicts: readonly Verdict[]): readonly DomainRollup[] {
  const rollups: DomainRollup[] = [];
  for (const domain of CCM_DOMAINS) {
    const inDomain = verdicts.filter((verdict) => domainOfCcmId(verdict.ccmId) === domain);
    if (inDomain.length > 0) {
      rollups.push({
        domain,
        controls: tally(controlStatuses(inDomain)),
        findings: tally(inDomain.map((verdict) => verdict.status)),
      });
    }
  }
  return rollups;
}

/**
 * Assembles the report. `metadata` (including the timestamp) is injected rather
 * than read from the clock, so the same input yields a byte-identical report.
 */
export function buildReport(verdicts: readonly Verdict[], metadata: RunMetadata): Report {
  validateMetadata(metadata);
  assertVerdictsAreWellFormed(verdicts);

  const controls = tally(controlStatuses(verdicts));
  const findings = tally(verdicts.map((verdict) => verdict.status));
  const headline: Headline = controls.fail > 0 ? "fail" : "pass";

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    metadata,
    headline,
    controls,
    findings,
    domains: rollUpByDomain(verdicts),
    verdicts,
  };
}
