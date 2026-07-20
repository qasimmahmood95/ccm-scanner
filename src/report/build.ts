import { CCM_DOMAINS, domainOfCcmId } from "../model/ccm.js";
import { checkIdProblem } from "../model/check-id.js";
import { compareVerdicts, type Status, type Verdict } from "../model/verdict.js";
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
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$/;

const STATUSES: readonly Status[] = ["pass", "fail", "not_applicable"];

/** True when y-m-d is a real calendar date (rejects 2026-02-30, which Date rolls over). */
function isRealCalendarDate(year: number, month: number, day: number): boolean {
  const probe = new Date(Date.UTC(year, month - 1, day));
  return (
    probe.getUTCFullYear() === year &&
    probe.getUTCMonth() === month - 1 &&
    probe.getUTCDate() === day
  );
}

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
    if (typeof value !== "string" || value.trim() === "") {
      throw new Error(`report metadata ${field} must be a non-empty string`);
    }
  }
  if (!DIGEST_PATTERN.test(metadata.input.digest)) {
    throw new Error(
      `report metadata input.digest must be a 64-character lowercase hex sha256, got ` +
        `"${metadata.input.digest}"`,
    );
  }

  const match = TIMESTAMP_PATTERN.exec(metadata.generatedAt);
  if (match === null) {
    throw new Error(
      `report metadata generatedAt must be an ISO-8601 timestamp with a timezone, got ` +
        `"${metadata.generatedAt}"`,
    );
  }
  // The pattern only checks shape; "2026-99-99T00:00:00Z" and "2026-02-30..." pass it.
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (!isRealCalendarDate(year, month, day) || Number.isNaN(Date.parse(metadata.generatedAt))) {
    throw new Error(`report metadata generatedAt is not a real date: "${metadata.generatedAt}"`);
  }
}

/**
 * Verdicts are checked here as well as at construction, because this is the
 * last gate before a document is emitted. `verdictOf` guards the path checks
 * take, but a deserialised report or a future ingest lane can reach this
 * function without passing through it, and the published schema is only
 * meaningful if the emitter cannot produce something that violates it.
 *
 * The domain check matters most: a verdict outside the in-scope domains would
 * be counted in the totals but omitted from every per-domain section — a FAIL
 * that renders as a headline with no detail.
 */
function assertVerdictsAreWellFormed(verdicts: readonly Verdict[]): void {
  for (const verdict of verdicts) {
    const where = `verdict from check "${verdict.checkId}"`;

    if (domainOfCcmId(verdict.ccmId) === undefined) {
      throw new Error(
        `${where} has ccmId "${verdict.ccmId}", which is not an in-scope CCM control id ` +
          `(expected e.g. "IVS-03"); it would be dropped from the report`,
      );
    }

    const idProblem = checkIdProblem(verdict.checkId);
    if (idProblem !== undefined) {
      throw new Error(`${where} has an invalid checkId: ${idProblem}`);
    }

    const checkDomain = verdict.checkId.slice(0, verdict.checkId.indexOf("/")).toUpperCase();
    if (checkDomain !== domainOfCcmId(verdict.ccmId)) {
      throw new Error(
        `${where} is namespaced to ${checkDomain} but its control ${verdict.ccmId} is not`,
      );
    }

    if (!STATUSES.includes(verdict.status)) {
      throw new Error(`${where} has unknown status "${String(verdict.status)}"`);
    }

    if (typeof verdict.ccmTitle !== "string" || verdict.ccmTitle.trim() === "") {
      throw new Error(`${where} has an empty ccmTitle`);
    }

    if (verdict.status === "not_applicable") {
      if (typeof verdict.reason !== "string" || verdict.reason.trim() === "") {
        throw new Error(`${where} is not_applicable but carries no reason`);
      }
    } else if (verdict.evidence.length === 0) {
      throw new Error(`${where} is "${verdict.status}" but carries no evidence`);
    }

    // Present-but-wrong is as invalid as absent: the schema types these as
    // non-empty strings, and a non-TS caller (a deserialised report, an ingest
    // adapter) can put anything here.
    if (verdict.reason !== undefined) {
      if (typeof verdict.reason !== "string" || verdict.reason.trim() === "") {
        throw new Error(`${where} has a reason that is not a non-empty string`);
      }
    }

    for (const item of verdict.evidence) {
      if (typeof item.resourceAddress !== "string" || item.resourceAddress.trim() === "") {
        throw new Error(`${where} has evidence with an empty resourceAddress`);
      }
      // Empty is rejected as well as absent: every other string field is
      // required non-empty, and allowing "" here would mean two verdicts that
      // render differently (the renderer omits an absent key and emits an
      // empty one) could compare equal.
      if (item.attribute !== undefined) {
        if (typeof item.attribute !== "string" || item.attribute.trim() === "") {
          throw new Error(`${where} has evidence whose attribute is not a non-empty string`);
        }
      }
      if (item.expected !== undefined) {
        if (typeof item.expected !== "string" || item.expected.trim() === "") {
          throw new Error(`${where} has evidence whose expected is not a non-empty string`);
        }
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
 * than read from the clock, and verdicts are re-sorted here rather than trusting
 * the caller's order, so the same input yields a byte-identical report whatever
 * produced the verdicts.
 */
export function buildReport(
  verdicts: readonly Verdict[],
  metadata: RunMetadata,
  warnings: readonly string[] = [],
): Report {
  validateMetadata(metadata);
  assertVerdictsAreWellFormed(verdicts);

  const ordered = [...verdicts].sort(compareVerdicts);
  const controls = tally(controlStatuses(ordered));
  const findings = tally(ordered.map((verdict) => verdict.status));
  const headline: Headline = controls.fail > 0 ? "fail" : "pass";

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    metadata,
    headline,
    controls,
    findings,
    domains: rollUpByDomain(ordered),
    warnings: [...warnings],
    verdicts: ordered,
  };
}
