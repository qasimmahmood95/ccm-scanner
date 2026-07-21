/**
 * Choosing an adapter for an input document.
 *
 * Sniffing rather than requiring a flag, because the two formats are trivially
 * distinguishable and making people declare what the file obviously is invites
 * them to declare it wrongly. An explicit override exists for the case where
 * the sniff is wrong, and a document matching neither shape is an error naming
 * both — never a guess, and never an empty model that scans clean.
 */
import { IngestError } from "./errors.js";
import { isRecord } from "./json.js";
import { ingestSnapshot, looksLikeSnapshot, SNAPSHOT_MARKER } from "./snapshot.js";
import { ingestTerraformPlan, type IngestResult } from "./terraform-plan.js";

export type InputFormat = "terraform" | "snapshot";

export const INPUT_FORMATS: readonly InputFormat[] = ["terraform", "snapshot"];

/**
 * The format a document appears to be, or `undefined` when it is neither.
 *
 * Only the snapshot marker is positive evidence; everything else is left to the
 * Terraform adapter, whose own errors already explain the shapes it accepts
 * (including the `terraform plan -json` log-stream mistake).
 */
export function detectFormat(raw: string): InputFormat | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Not JSON at all: hand it to the Terraform adapter, which distinguishes
    // "not JSON" from "the wrong Terraform command" in its error.
    return "terraform";
  }
  if (!isRecord(parsed)) {
    return undefined;
  }
  if (looksLikeSnapshot(parsed)) {
    return "snapshot";
  }
  const terraformish =
    "planned_values" in parsed ||
    "values" in parsed ||
    "format_version" in parsed ||
    "terraform_version" in parsed;
  return terraformish ? "terraform" : undefined;
}

export function ingest(raw: string, source: string, format?: InputFormat): IngestResult {
  const chosen = format ?? detectFormat(raw);
  if (chosen === undefined) {
    throw new IngestError(
      source,
      "input matches neither supported format. Expected `terraform show -json` output " +
        `(with "planned_values" or "values"), or a ccm-scanner snapshot (with a ` +
        `"${SNAPSHOT_MARKER}" version marker). See docs/adr/0004-snapshot-lane.md.`,
    );
  }
  return chosen === "snapshot" ? ingestSnapshot(raw, source) : ingestTerraformPlan(raw, source);
}
