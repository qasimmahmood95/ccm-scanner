import { CCM_DOMAINS, domainOfCcmId } from "../model/ccm.js";
import type { Verdict } from "../model/verdict.js";
import {
  REPORT_SCHEMA_VERSION,
  type DomainRollup,
  type Headline,
  type Report,
  type RunMetadata,
  type StatusCounts,
} from "./types.js";

function countStatuses(verdicts: readonly Verdict[]): StatusCounts {
  let pass = 0;
  let fail = 0;
  let notApplicable = 0;
  for (const verdict of verdicts) {
    if (verdict.status === "pass") {
      pass += 1;
    } else if (verdict.status === "fail") {
      fail += 1;
    } else {
      notApplicable += 1;
    }
  }
  return { pass, fail, notApplicable, total: verdicts.length };
}

/** Roll-ups in canonical domain order, omitting domains with no verdicts. */
function rollUpByDomain(verdicts: readonly Verdict[]): readonly DomainRollup[] {
  const rollups: DomainRollup[] = [];
  for (const domain of CCM_DOMAINS) {
    const inDomain = verdicts.filter((verdict) => domainOfCcmId(verdict.ccmId) === domain);
    if (inDomain.length > 0) {
      rollups.push({ domain, ...countStatuses(inDomain) });
    }
  }
  return rollups;
}

/**
 * Assembles the report. `metadata` (including the timestamp) is injected rather
 * than read from the clock, so the same input yields a byte-identical report.
 */
export function buildReport(verdicts: readonly Verdict[], metadata: RunMetadata): Report {
  const totals = countStatuses(verdicts);
  const headline: Headline = totals.fail > 0 ? "fail" : "pass";
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    metadata,
    headline,
    totals,
    domains: rollUpByDomain(verdicts),
    verdicts,
  };
}
