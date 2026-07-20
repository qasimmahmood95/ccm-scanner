import type { CcmDomain } from "../model/ccm.js";
import type { Verdict } from "../model/verdict.js";

/**
 * Bumped when the report JSON shape changes.
 *
 * Minor for an added field (a reader that ignores unknown keys is unaffected,
 * though the published schema sets `additionalProperties: false`, so documents
 * do not validate across versions); major for a removal or a retype.
 */
export const REPORT_SCHEMA_VERSION = "1.1.0";

export interface ToolInfo {
  readonly name: string;
  readonly version: string;
}

export interface InputInfo {
  /** Where the model came from, e.g. `terraform-plan:plan.json`. */
  readonly source: string;
  /** sha256 (hex, lowercase) of the input. */
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

/**
 * Counts are reported at two granularities, because they answer different
 * questions and conflating them overstates coverage:
 *
 * - **controls** — distinct CCM controls assessed. A control is `fail` if any
 *   of its findings failed, else `pass` if any passed, else `not_applicable`.
 *   This is the number an auditor cares about.
 * - **findings** — individual verdicts, typically one per resource examined.
 */
export interface DomainRollup {
  readonly domain: CcmDomain;
  readonly controls: StatusCounts;
  readonly findings: StatusCounts;
}

/** `fail` when any control failed, otherwise `pass`. Drives the CLI exit code. */
export type Headline = "pass" | "fail";

export interface Report {
  readonly schemaVersion: string;
  readonly metadata: RunMetadata;
  readonly headline: Headline;
  readonly controls: StatusCounts;
  readonly findings: StatusCounts;
  /** Only domains that produced verdicts, in canonical domain order. */
  readonly domains: readonly DomainRollup[];
  /**
   * Non-fatal notes from ingestion — a skipped entry, an ambiguous shape.
   *
   * These belong in the report rather than on stderr: a scan that quietly
   * dropped a module subtree produces a clean-looking report over an input it
   * did not fully read, and an auditor reading the artifact months later has no
   * other way to know.
   */
  readonly warnings: readonly string[];
  readonly verdicts: readonly Verdict[];
}
