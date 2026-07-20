/**
 * S3 specifics shared by the CEK, LOG and IVS domains.
 *
 * The correlation machinery itself is generic and lives in `correlate.ts`;
 * what belongs here is what is true of S3 in particular.
 */
import type { Resource } from "../../model/resource.js";
import { readAttribute } from "./attributes.js";
import type { Qualification } from "./correlate.js";

/**
 * The four flags of a public-access block. All must be on: leaving any one off
 * leaves a documented route to making the bucket public, so a partial block is
 * a failure rather than a partial pass.
 */
export const PUBLIC_ACCESS_BLOCK_FLAGS = [
  "block_public_acls",
  "block_public_policy",
  "ignore_public_acls",
  "restrict_public_buckets",
] as const;

/**
 * Whether a public-access-block resource enables all four flags.
 *
 * Terraform defaults every flag to `false` when omitted, so an absent flag is a
 * genuine "not blocked" rather than missing information — but an *unknown* one
 * is neither, and is reported as such.
 */
export function qualifiesAsFullBlock(block: Resource): Qualification {
  for (const flag of PUBLIC_ACCESS_BLOCK_FLAGS) {
    const read = readAttribute(block, flag);
    if (read.kind === "unknown") {
      return { kind: "unresolvable", attribute: flag, cause: "unknown" };
    }
    if (read.kind !== "value" || read.value !== true) {
      return { kind: "no" };
    }
  }
  return { kind: "yes" };
}
