/**
 * CCM framework constants.
 *
 * Domain codes are stable across CCM v4.x, whereas individual control numbers
 * are not (v4.1 renumbers IAM). That is precisely why check IDs are namespaced
 * by domain rather than by control number — see ADR-0003.
 */

/** The CCM domains in scope for v1 (see docs/control-mapping.md). */
export const CCM_DOMAINS = ["IAM", "LOG", "CEK", "IVS"] as const;

export type CcmDomain = (typeof CCM_DOMAINS)[number];

/** Verbatim CCM v4.0 domain titles, used in the human-readable report. */
export const CCM_DOMAIN_TITLES: Readonly<Record<CcmDomain, string>> = {
  IAM: "Identity & Access Management",
  LOG: "Logging & Monitoring",
  CEK: "Cryptography, Encryption & Key Management",
  IVS: "Infrastructure & Virtualization Security",
};

/** The CCM release this build is pinned to (ADR-0003). Echoed in every report. */
export const CCM_VERSION = "v4.0.13";

const CCM_ID_PATTERN = /^(IAM|LOG|CEK|IVS)-\d{2}$/;

export function isCcmDomain(value: string): value is CcmDomain {
  return (CCM_DOMAINS as readonly string[]).includes(value);
}

/**
 * Derives the domain from a CCM control id, e.g. `"IVS-03"` -> `"IVS"`.
 * Returns `undefined` when the id is not a well-formed in-scope control id.
 */
export function domainOfCcmId(ccmId: string): CcmDomain | undefined {
  const match = CCM_ID_PATTERN.exec(ccmId);
  if (match === null) {
    return undefined;
  }
  const domain = match[1];
  return domain !== undefined && isCcmDomain(domain) ? domain : undefined;
}
