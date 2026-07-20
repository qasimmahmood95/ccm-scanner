import { CCM_DOMAINS, domainOfCcmId, type CcmDomain } from "../model/ccm.js";
import { checkIdProblem } from "../model/check-id.js";
import { compareStrings } from "../util/compare.js";
import type { Check } from "./check.js";

declare const VALIDATED: unique symbol;

/**
 * A check that has passed registry validation. Only `createRegistry` mints
 * these, so `evaluate` cannot be handed a check that skipped the invariants.
 */
export interface ValidatedCheck extends Check {
  readonly [VALIDATED]: true;
}

/** Narrows which checks to run. An absent field means "no constraint". */
export interface CheckSelector {
  readonly domains?: readonly CcmDomain[];
  readonly ccmIds?: readonly string[];
}

export interface ControlRegistry {
  /** All registered checks, in stable (ccmId, checkId) order. */
  readonly checks: readonly ValidatedCheck[];
  /**
   * Checks matching the selector. Throws if the selector names a domain or
   * control with no registered check, or matches nothing — a typo in
   * `--controls` must not silently produce an empty, passing scan.
   */
  select(selector?: CheckSelector): readonly ValidatedCheck[];
}

function validateCheck(
  check: Check,
  seenCheckIds: Set<string>,
  titlesByControl: Map<string, string>,
): void {
  const idProblem = checkIdProblem(check.checkId);
  if (idProblem !== undefined) {
    throw new Error(`invalid checkId "${check.checkId}": ${idProblem}.`);
  }

  const ccmDomain = domainOfCcmId(check.ccmId);
  if (ccmDomain === undefined) {
    const domains = CCM_DOMAINS.join(", ");
    throw new Error(
      `invalid ccmId "${check.ccmId}" on check "${check.checkId}": expected e.g. "IVS-03" ` +
        `with a domain in (${domains}).`,
    );
  }

  const checkDomain = check.checkId.slice(0, check.checkId.indexOf("/")).toUpperCase();
  if (checkDomain !== ccmDomain) {
    throw new Error(
      `check "${check.checkId}" is namespaced to ${checkDomain} but its control ` +
        `${check.ccmId} belongs to ${ccmDomain}.`,
    );
  }

  if (check.ccmTitle.trim() === "") {
    throw new Error(`check "${check.checkId}" is missing its verbatim CCM title.`);
  }

  // Two checks covering one control must agree on its title, or the report
  // would show whichever happened to sort first and hide the drift from
  // docs/control-mapping.md.
  const knownTitle = titlesByControl.get(check.ccmId);
  if (knownTitle !== undefined && knownTitle !== check.ccmTitle) {
    throw new Error(
      `control ${check.ccmId} has conflicting titles: "${knownTitle}" and ` +
        `"${check.ccmTitle}" (on check "${check.checkId}").`,
    );
  }
  titlesByControl.set(check.ccmId, check.ccmTitle);

  if (seenCheckIds.has(check.checkId)) {
    throw new Error(`duplicate checkId "${check.checkId}".`);
  }
  seenCheckIds.add(check.checkId);
}

/**
 * Builds a registry, validating every check up front. Invalid registrations are
 * a programming error and fail loudly rather than producing a subtly wrong report.
 */
export function createRegistry(checks: readonly Check[]): ControlRegistry {
  const seenCheckIds = new Set<string>();
  const titlesByControl = new Map<string, string>();
  for (const check of checks) {
    validateCheck(check, seenCheckIds, titlesByControl);
  }

  // Branding is the point of the validation above: everything downstream can
  // now rely on these invariants holding. `ValidatedCheck` adds only a phantom
  // symbol, so a double cast is the only way to mint one.
  const ordered = [...checks].sort(
    (a, b) => compareStrings(a.ccmId, b.ccmId) || compareStrings(a.checkId, b.checkId),
  ) as unknown as readonly ValidatedCheck[];

  const knownDomains = new Set<string>();
  const knownCcmIds = new Set<string>();
  for (const check of ordered) {
    const domain = domainOfCcmId(check.ccmId);
    if (domain !== undefined) {
      knownDomains.add(domain);
    }
    knownCcmIds.add(check.ccmId);
  }

  return {
    checks: ordered,
    select(selector: CheckSelector = {}): readonly ValidatedCheck[] {
      const { domains, ccmIds } = selector;

      if (domains !== undefined) {
        const unknown = domains.filter((domain) => !knownDomains.has(domain));
        if (unknown.length > 0) {
          throw new Error(`no registered checks for domain(s): ${unknown.join(", ")}`);
        }
      }
      if (ccmIds !== undefined) {
        const unknown = ccmIds.filter((ccmId) => !knownCcmIds.has(ccmId));
        if (unknown.length > 0) {
          throw new Error(`no registered checks for control(s): ${unknown.join(", ")}`);
        }
      }

      const selected = ordered.filter((check) => {
        if (domains !== undefined) {
          const domain = domainOfCcmId(check.ccmId);
          if (domain === undefined || !domains.includes(domain)) {
            return false;
          }
        }
        if (ccmIds !== undefined && !ccmIds.includes(check.ccmId)) {
          return false;
        }
        return true;
      });

      const constrained = domains !== undefined || ccmIds !== undefined;
      if (constrained && selected.length === 0) {
        throw new Error("selector matched no registered checks");
      }
      return selected;
    },
  };
}
