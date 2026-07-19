import type { ResourceModel } from "../model/resource.js";
import { verdictOf, type Finding, type Verdict } from "../model/verdict.js";
import { compareStrings } from "../util/compare.js";
import type { ValidatedCheck } from "./registry.js";

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
 *
 * Only checks that came through `createRegistry` are accepted, so the registry
 * invariants cannot be routed around. The control identity is stamped here
 * rather than trusted from the check, and anything a check does wrong surfaces
 * with the id of the check that did it.
 */
export function evaluate(
  checks: readonly ValidatedCheck[],
  model: ResourceModel,
): readonly Verdict[] {
  const verdicts: Verdict[] = [];

  for (const check of checks) {
    const control = {
      ccmId: check.ccmId,
      ccmTitle: check.ccmTitle,
      checkId: check.checkId,
    };

    let findings: readonly Finding[];
    try {
      const returned = check.run(model);
      if (!Array.isArray(returned)) {
        throw new TypeError(`expected an array of findings, received ${typeof returned}`);
      }
      findings = returned;
    } catch (cause) {
      throw new Error(`check "${check.checkId}" (${check.ccmId}) failed while evaluating`, {
        cause,
      });
    }

    for (const finding of findings) {
      verdicts.push(verdictOf(control, finding));
    }
  }

  return verdicts.sort(compareVerdicts);
}
