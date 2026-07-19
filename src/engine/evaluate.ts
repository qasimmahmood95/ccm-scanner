import type { ResourceModel } from "../model/resource.js";
import type { Verdict } from "../model/verdict.js";
import { compareStrings } from "../util/compare.js";
import type { Check } from "./check.js";

function firstAddress(verdict: Verdict): string {
  return verdict.evidence[0]?.resourceAddress ?? "";
}

function compareVerdicts(a: Verdict, b: Verdict): number {
  return (
    compareStrings(a.ccmId, b.ccmId) ||
    compareStrings(a.checkId, b.checkId) ||
    compareStrings(firstAddress(a), firstAddress(b)) ||
    compareStrings(a.status, b.status)
  );
}

/**
 * Runs the given checks over the model and returns their verdicts in a stable,
 * explicit order (not registration order), so the same input always yields a
 * byte-identical report.
 */
export function evaluate(checks: readonly Check[], model: ResourceModel): readonly Verdict[] {
  const verdicts: Verdict[] = [];
  for (const check of checks) {
    verdicts.push(...check.run(model));
  }
  return verdicts.sort(compareVerdicts);
}
