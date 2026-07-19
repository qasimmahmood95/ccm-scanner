import type { CcmDomain } from "../model/ccm.js";
import type { Verdict } from "../model/verdict.js";

/** Bumped when the report JSON shape changes incompatibly. */
export const REPORT_SCHEMA_VERSION = "1.0.0";

export interface ToolInfo {
  readonly name: string;
  readonly version: string;
}

export interface InputInfo {
  /** Where the model came from, e.g. `terraform-plan:plan.json`. */
  readonly source: string;
  /** sha256 (hex) of the raw input bytes. */
  readonly digest: string;
}

export interface RunMetadata {
  readonly tool: ToolInfo;
  /** Pinned CCM release, e.g. `v4.0.13` (ADR-0003). */
  readonly ccmVersion: string;
  readonly input: InputInfo;
  /** ISO-8601 timestamp, injected by the caller so reports stay reproducible. */
  readonly generatedAt: string;
}

export interface StatusCounts {
  readonly pass: number;
  readonly fail: number;
  readonly notApplicable: number;
  readonly total: number;
}

export interface DomainRollup extends StatusCounts {
  readonly domain: CcmDomain;
}

/** `fail` when any control failed, otherwise `pass`. Drives the CLI exit code. */
export type Headline = "pass" | "fail";

export interface Report {
  readonly schemaVersion: string;
  readonly metadata: RunMetadata;
  readonly headline: Headline;
  readonly totals: StatusCounts;
  /** Only domains that produced verdicts, in canonical domain order. */
  readonly domains: readonly DomainRollup[];
  readonly verdicts: readonly Verdict[];
}
