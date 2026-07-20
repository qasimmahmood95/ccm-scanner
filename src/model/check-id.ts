/**
 * Check-id rules, shared so the registry, the report emitter and the published
 * schema cannot drift apart.
 *
 * A check id is `<domain>/<slug>`: the CCM domain code (stable across CCM v4.x)
 * plus a semantic slug. It must not embed the CCM control *number*, which CCM
 * renumbers between versions — see ADR-0003.
 */

export const CHECK_ID_PATTERN = /^(iam|log|cek|ivs)\/[a-z0-9]+(?:-[a-z0-9]+)*$/;

/**
 * A CCM control number anywhere in the slug, in any of the shapes people
 * reach for: `cek-03`, `cek03`, `cek-3`.
 */
const EMBEDDED_CONTROL_NUMBER = /(iam|log|cek|ivs)-?[0-9]/;

/**
 * Returns a human-readable problem with the check id, or `undefined` when it is
 * well formed.
 */
export function checkIdProblem(checkId: string): string | undefined {
  if (!CHECK_ID_PATTERN.test(checkId)) {
    return (
      'expected "<domain>/<slug>" where domain is one of (iam|log|cek|ivs) and ' +
      "slug is kebab-case; check IDs must not embed the CCM control number (ADR-0003)"
    );
  }
  const slug = checkId.slice(checkId.indexOf("/") + 1);
  if (EMBEDDED_CONTROL_NUMBER.test(slug)) {
    return "the slug must not embed the CCM control number (ADR-0003); name the check for what it verifies instead";
  }
  return undefined;
}
