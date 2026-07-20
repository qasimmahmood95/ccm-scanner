/**
 * Removing values Terraform marked sensitive before they reach a report.
 *
 * `terraform show -json` of *state* puts real secrets in `values` — an RDS
 * password, a private key — and marks them in `sensitive_values`. The report is
 * an artifact people commit, attach to a ticket and hand to an auditor, so a
 * secret that reaches it has been published. Ingest carries the marks through
 * on `Resource.sensitiveAttributes`; this is where they are honoured.
 *
 * Redaction happens between evaluation and report building rather than in a
 * renderer, so every output format is covered by construction and a new
 * renderer cannot forget.
 *
 * Note the limits, because a security control that overstates itself is worse
 * than one that does not exist. This redacts:
 *
 * - an evidence entry that *cites* a sensitive attribute, including a nested
 *   path under one (`master[0].password` under a sensitive `master`);
 * - any sensitive key found while walking an object- or array-valued
 *   `observed`, to `MAX_DEPTH`.
 *
 * It does **not** redact a secret a check has interpolated into a free-text
 * `observed`, `expected` or `reason` — nothing there is machine-identifiable —
 * so checks must not build strings out of attribute values. Nor does it know
 * about a secret the input never marked sensitive.
 */
import type { ResourceModel } from "../model/resource.js";
import type { Evidence, Verdict } from "../model/verdict.js";

export const REDACTED = "[redacted: marked sensitive by Terraform]";

/** The top-level attribute an evidence path refers to. */
function topLevel(attribute: string): string {
  const [head] = attribute.split(/[.[]/, 1);
  return head ?? attribute;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Bounds the walk. Evidence is shallow in practice; the cap only stops a
 * pathological or cyclic structure turning redaction into a stack overflow.
 */
const MAX_DEPTH = 20;

/**
 * Replaces the values of sensitive keys anywhere in the structure, leaving the
 * shape visible.
 *
 * Arrays are walked as well as objects: `[{ Principal: … }]` is the ordinary
 * shape of a policy-statement observation, so stopping at the top level would
 * leave the most likely container unexamined.
 */
function redactKeys(value: unknown, sensitive: ReadonlySet<string>, depth = 0): unknown {
  if (depth >= MAX_DEPTH) {
    return value;
  }
  if (Array.isArray(value)) {
    let changed = false;
    const items = value.map((item) => {
      const redacted = redactKeys(item, sensitive, depth + 1);
      changed ||= redacted !== item;
      return redacted;
    });
    return changed ? items : value;
  }
  if (!isPlainObject(value)) {
    return value;
  }
  let changed = false;
  const result: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (sensitive.has(key)) {
      result[key] = REDACTED;
      changed = true;
      continue;
    }
    const redacted = redactKeys(entry, sensitive, depth + 1);
    changed ||= redacted !== entry;
    result[key] = redacted;
  }
  return changed ? result : value;
}

function redactEvidence(evidence: Evidence, sensitive: ReadonlySet<string>): Evidence {
  if (evidence.attribute !== undefined && sensitive.has(topLevel(evidence.attribute))) {
    return { ...evidence, observed: REDACTED };
  }
  const observed = redactKeys(evidence.observed, sensitive);
  return observed === evidence.observed ? evidence : { ...evidence, observed };
}

/**
 * Redacts every evidence value that Terraform marked sensitive.
 *
 * Returns the same verdicts when nothing needed redacting, so the common case
 * allocates nothing and stays trivially deterministic.
 */
export function redactSensitive(
  verdicts: readonly Verdict[],
  model: ResourceModel,
): readonly Verdict[] {
  const sensitiveByAddress = new Map<string, ReadonlySet<string>>();
  for (const resource of model.resources) {
    if (resource.sensitiveAttributes.length > 0) {
      sensitiveByAddress.set(resource.address, new Set(resource.sensitiveAttributes));
    }
  }
  if (sensitiveByAddress.size === 0) {
    return verdicts;
  }

  return verdicts.map((verdict) => {
    let changed = false;
    const evidence = verdict.evidence.map((entry) => {
      const sensitive = sensitiveByAddress.get(entry.resourceAddress);
      if (sensitive === undefined) {
        return entry;
      }
      const redacted = redactEvidence(entry, sensitive);
      changed ||= redacted !== entry;
      return redacted;
    });
    return changed ? { ...verdict, evidence } : verdict;
  });
}
