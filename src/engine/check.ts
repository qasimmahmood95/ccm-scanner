import type { ResourceModel } from "../model/resource.js";
import type { Finding } from "../model/verdict.js";

/**
 * A check is a pure function over the model. Same input must always produce the
 * same findings — this is what makes the evidence pack reproducible and the
 * golden-file tests meaningful.
 *
 * Checks return findings, not verdicts: the engine attaches the control
 * identity, so a check cannot attribute a result to the wrong control.
 */
export type CheckFn = (model: ResourceModel) => readonly Finding[];

export interface Check {
  /**
   * Stable `<domain>/<slug>` identifier, e.g. `ivs/no-open-admin-ports`.
   * Must NOT embed the CCM control number — CCM renumbers controls between
   * versions (ADR-0003). Enforced by the registry.
   */
  readonly checkId: string;
  /** e.g. `IVS-03` — must have a row in docs/control-mapping.md. */
  readonly ccmId: string;
  /** Verbatim CCM v4.0 title. */
  readonly ccmTitle: string;
  readonly run: CheckFn;
}
