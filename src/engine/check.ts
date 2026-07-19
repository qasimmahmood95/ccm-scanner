import type { ResourceModel } from "../model/resource.js";
import type { Verdict } from "../model/verdict.js";

/**
 * A check is a pure function over the resource model. Same input must always
 * produce the same verdicts — this is what makes the evidence pack
 * reproducible and the golden-file tests meaningful.
 */
export type CheckFn = (model: ResourceModel) => readonly Verdict[];

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
