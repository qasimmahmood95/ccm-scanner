/**
 * The verdict model — the atomic unit of a report.
 *
 * The constructors in this module enforce the rules from CLAUDE.md and
 * ADR-0003 mechanically: a `pass`/`fail` must carry evidence, and a
 * `not_applicable` must carry a reason. We never infer a verdict we cannot
 * evidence.
 */

export type Status = "pass" | "fail" | "not_applicable";

/** A single observation backing a verdict. */
export interface Evidence {
  /** Resource address the observation came from, e.g. `aws_security_group.web`. */
  readonly resourceAddress: string;
  /** Attribute path, e.g. `ingress[0].cidr_blocks`. */
  readonly attribute?: string;
  /** What we actually saw. */
  readonly observed: unknown;
  /** What compliance requires, human-readable. */
  readonly expected?: string;
}

export interface Verdict {
  /** e.g. `IVS-03` — MUST have a row in docs/control-mapping.md. */
  readonly ccmId: string;
  /** Verbatim CCM v4.0 title. */
  readonly ccmTitle: string;
  /** Stable `<domain>/<slug>` id, e.g. `ivs/no-open-admin-ports`. */
  readonly checkId: string;
  readonly status: Status;
  /** Required for `pass`/`fail`; empty for `not_applicable`. */
  readonly evidence: readonly Evidence[];
  /** Required when status is `not_applicable`. */
  readonly reason?: string;
}

/** Identifies the control a verdict belongs to. */
export interface ControlRef {
  readonly ccmId: string;
  readonly ccmTitle: string;
  readonly checkId: string;
}

function assertEvidenced(status: Status, control: ControlRef, evidence: readonly Evidence[]): void {
  if (evidence.length === 0) {
    throw new Error(
      `a "${status}" verdict for ${control.ccmId} (${control.checkId}) requires evidence`,
    );
  }
}

/** Builds a `pass` verdict. Evidence is required: a pass must be evidenced. */
export function pass(control: ControlRef, evidence: readonly Evidence[]): Verdict {
  assertEvidenced("pass", control, evidence);
  return { ...control, status: "pass", evidence };
}

/** Builds a `fail` verdict. Evidence is required: a fail must be evidenced. */
export function fail(control: ControlRef, evidence: readonly Evidence[]): Verdict {
  assertEvidenced("fail", control, evidence);
  return { ...control, status: "fail", evidence };
}

/**
 * Builds a `not_applicable` verdict. A non-empty reason is required — this is
 * the "never guess" rule from CLAUDE.md, enforced at construction.
 */
export function notApplicable(control: ControlRef, reason: string): Verdict {
  if (reason.trim() === "") {
    throw new Error(
      `a "not_applicable" verdict for ${control.ccmId} (${control.checkId}) requires a reason`,
    );
  }
  return { ...control, status: "not_applicable", evidence: [], reason };
}
