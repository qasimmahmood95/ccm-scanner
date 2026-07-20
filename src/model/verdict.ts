/**
 * The finding/verdict model — the atomic unit of a report.
 *
 * Checks emit **findings** (a status plus its evidence). The engine stamps the
 * owning control onto each finding to produce a **verdict**. Checks therefore
 * cannot mis-attribute a result to the wrong control, and the ADR-0003
 * invariants — pass/fail must be evidenced, not-applicable must carry a reason
 * — are enforced in one place that every verdict passes through.
 */

import { compareStrings } from "../util/compare.js";
import { toJsonSafe } from "../util/json-safe.js";

export type Status = "pass" | "fail" | "not_applicable";

/** A single observation backing a finding. */
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

/** What a check reports about one resource (or about the input as a whole). */
export interface Finding {
  readonly status: Status;
  readonly evidence: readonly Evidence[];
  readonly reason?: string;
}

/** Identifies the control a verdict belongs to. */
export interface ControlRef {
  readonly ccmId: string;
  readonly ccmTitle: string;
  readonly checkId: string;
}

export interface Verdict extends ControlRef {
  readonly status: Status;
  /** Required for `pass`/`fail`; empty for `not_applicable`. */
  readonly evidence: readonly Evidence[];
  /** Required when status is `not_applicable`. */
  readonly reason?: string;
}

/** Reports compliance, evidenced. */
export function pass(evidence: readonly Evidence[]): Finding {
  return { status: "pass", evidence };
}

/** Reports non-compliance, evidenced. */
export function fail(evidence: readonly Evidence[]): Finding {
  return { status: "fail", evidence };
}

/**
 * Reports that the control cannot be assessed from this input. The reason is
 * mandatory — we never infer a Pass/Fail we cannot evidence.
 */
export function notApplicable(reason: string): Finding {
  return { status: "not_applicable", evidence: [], reason };
}

/**
 * Stamps a control onto a finding, enforcing the verdict invariants. This is
 * the only supported way to build a `Verdict`.
 */
export function verdictOf(control: ControlRef, finding: Finding): Verdict {
  if (finding.status === "not_applicable") {
    const reason = finding.reason ?? "";
    if (reason.trim() === "") {
      throw new Error(
        `a "not_applicable" finding for ${control.ccmId} (${control.checkId}) requires a reason`,
      );
    }
    return { ...control, status: "not_applicable", evidence: [], reason };
  }

  if (finding.evidence.length === 0) {
    throw new Error(
      `a "${finding.status}" finding for ${control.ccmId} (${control.checkId}) requires evidence`,
    );
  }

  return { ...control, status: finding.status, evidence: finding.evidence };
}

function firstAddress(verdict: Verdict): string {
  return verdict.evidence[0]?.resourceAddress ?? "";
}

/** Canonical serialisation of a verdict's evidence, used as the final tie-break. */
function evidenceKey(verdict: Verdict): string {
  return (
    JSON.stringify(
      verdict.evidence.map((item) => [
        item.resourceAddress,
        item.attribute ?? "",
        item.expected ?? "",
        toJsonSafe(item.observed),
      ]),
    ) ?? ""
  );
}

/**
 * A **total** order over verdicts, so a report never depends on the order
 * checks happened to emit in.
 *
 * The tie-breaks matter: a single check routinely emits several findings for
 * one resource (one per ingress rule, say), and those agree on control, check,
 * first address and status. Without a final discriminator `Array.sort`'s
 * stability would let input order leak into the output bytes.
 */
export function compareVerdicts(a: Verdict, b: Verdict): number {
  return (
    compareStrings(a.ccmId, b.ccmId) ||
    compareStrings(a.checkId, b.checkId) ||
    compareStrings(firstAddress(a), firstAddress(b)) ||
    compareStrings(a.status, b.status) ||
    compareStrings(a.reason ?? "", b.reason ?? "") ||
    compareStrings(evidenceKey(a), evidenceKey(b))
  );
}
