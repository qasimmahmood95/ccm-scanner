import type { ResourceModel } from "../model/resource.js";
import { compareVerdicts, verdictOf, type Finding, type Verdict } from "../model/verdict.js";
import type { ValidatedCheck } from "./registry.js";

function isFinding(value: unknown): value is Finding {
  return typeof value === "object" && value !== null && "status" in value;
}

/**
 * Runs the given checks over the model and returns their verdicts in a stable,
 * explicit order (not registration order), so the same input always yields a
 * byte-identical report.
 *
 * Only checks that came through `createRegistry` are accepted, so the registry
 * invariants cannot be routed around. The control identity is stamped here
 * rather than trusted from the check, and anything a check does wrong surfaces
 * with the id of the check that did it rather than as an anonymous stack trace.
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

    try {
      const returned = check.run(model);
      if (!Array.isArray(returned)) {
        throw new TypeError(`expected an array of findings, received ${typeof returned}`);
      }
      for (const finding of returned) {
        if (!isFinding(finding)) {
          throw new TypeError(`returned a finding that is not an object with a status`);
        }
        verdicts.push(verdictOf(control, finding));
      }
    } catch (cause) {
      throw new Error(`check "${check.checkId}" (${check.ccmId}) failed while evaluating`, {
        cause,
      });
    }
  }

  return verdicts.sort(compareVerdicts);
}
