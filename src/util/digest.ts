import { createHash } from "node:crypto";

/**
 * sha256 of the given content, hex-encoded.
 *
 * Recorded in report metadata so a verdict set can be tied to the exact input
 * it was derived from — part of what makes the report audit evidence. Pass a
 * `Uint8Array` to hash the raw bytes; a `string` is hashed as UTF-8, which is
 * only equivalent for input that was UTF-8 to begin with.
 */
export function sha256Hex(content: string | Uint8Array): string {
  return createHash("sha256").update(content).digest("hex");
}
