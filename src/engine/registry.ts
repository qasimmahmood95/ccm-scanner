import { CCM_DOMAINS, domainOfCcmId, type CcmDomain } from "../model/ccm.js";
import { compareStrings } from "../util/compare.js";
import type { Check } from "./check.js";

/** `<domain>/<slug>`, lowercase kebab slug. */
const CHECK_ID_PATTERN = /^(iam|log|cek|ivs)\/[a-z0-9]+(?:-[a-z0-9]+)*$/;

/**
 * A CCM control number anywhere in the slug. CCM renumbers controls between
 * versions, so binding a check's identity to a control number would force
 * cascading renames on every framework bump (ADR-0003). Rejecting the domain
 * prefix alone is not enough — `cek/cek-03-encryption` embeds it just as much
 * as `cek-03/encryption` does.
 */
const EMBEDDED_CONTROL_NUMBER = /(iam|log|cek|ivs)-[0-9]{2}/;

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

function validateCheck(check: Check, seen: Set<string>): void {
  const match = CHECK_ID_PATTERN.exec(check.checkId);
  if (match === null) {
    const domains = CCM_DOMAINS.map((domain) => domain.toLowerCase()).join("|");
    throw new Error(
      `invalid checkId "${check.checkId}": expected "<domain>/<slug>" where domain is ` +
        `one of (${domains}) and slug is kebab-case. Check IDs must not embed the CCM ` +
        `control number (ADR-0003).`,
    );
  }

  const slug = check.checkId.slice(check.checkId.indexOf("/") + 1);
  if (EMBEDDED_CONTROL_NUMBER.test(slug)) {
    throw new Error(
      `invalid checkId "${check.checkId}": the slug must not embed the CCM control ` +
        `number (ADR-0003); name the check for what it verifies instead.`,
    );
  }

  const ccmDomain = domainOfCcmId(check.ccmId);
  if (ccmDomain === undefined) {
    throw new Error(
      `invalid ccmId "${check.ccmId}" on check "${check.checkId}": expected e.g. "IVS-03".`,
    );
  }

  const checkDomain = (match[1] ?? "").toUpperCase();
  if (checkDomain !== ccmDomain) {
    throw new Error(
      `check "${check.checkId}" is namespaced to ${checkDomain} but its control ` +
        `${check.ccmId} belongs to ${ccmDomain}.`,
    );
  }

  if (check.ccmTitle.trim() === "") {
    throw new Error(`check "${check.checkId}" is missing its verbatim CCM title.`);
  }

  if (seen.has(check.checkId)) {
    throw new Error(`duplicate checkId "${check.checkId}".`);
  }
  seen.add(check.checkId);
}

/**
 * Builds a registry, validating every check up front. Invalid registrations are
 * a programming error and fail loudly rather than producing a subtly wrong report.
 */
export function createRegistry(checks: readonly Check[]): ControlRegistry {
  const seen = new Set<string>();
  for (const check of checks) {
    validateCheck(check, seen);
  }

  // Branding is the point of the validation above: everything downstream can
  // now rely on these invariants holding.
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
