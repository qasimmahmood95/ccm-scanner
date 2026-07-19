import { createHash } from "node:crypto";

/**
 * sha256 of the given content, hex-encoded.
 *
 * Recorded in report metadata so a verdict set can be tied to the exact input
 * bytes it was derived from — part of what makes the report audit evidence.
 */
export function sha256Hex(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}
