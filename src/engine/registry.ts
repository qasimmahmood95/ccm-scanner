import { CCM_DOMAINS, domainOfCcmId, type CcmDomain } from "../model/ccm.js";
import { compareStrings } from "../util/compare.js";
import type { Check } from "./check.js";

/**
 * `<domain>/<slug>`, lowercase kebab slug. This pattern structurally rejects
 * the CCM-numbered form (`iam-05/...`), which is the mechanical enforcement of
 * ADR-0003's version-independent check IDs.
 */
const CHECK_ID_PATTERN = /^(iam|log|cek|ivs)\/[a-z0-9]+(?:-[a-z0-9]+)*$/;

/** Narrows which checks to run. An absent field means "no constraint". */
export interface CheckSelector {
  readonly domains?: readonly CcmDomain[];
  readonly ccmIds?: readonly string[];
}

export interface ControlRegistry {
  /** All registered checks, in stable (ccmId, checkId) order. */
  readonly checks: readonly Check[];
  select(selector?: CheckSelector): readonly Check[];
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

  const ordered = [...checks].sort(
    (a, b) => compareStrings(a.ccmId, b.ccmId) || compareStrings(a.checkId, b.checkId),
  );

  return {
    checks: ordered,
    select(selector: CheckSelector = {}): readonly Check[] {
      return ordered.filter((check) => {
        if (selector.domains !== undefined) {
          const domain = domainOfCcmId(check.ccmId);
          if (domain === undefined || !selector.domains.includes(domain)) {
            return false;
          }
        }
        if (selector.ccmIds !== undefined && !selector.ccmIds.includes(check.ccmId)) {
          return false;
        }
        return true;
      });
    },
  };
}
