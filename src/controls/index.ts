import type { Check } from "../engine/check.js";
import { cekChecks } from "./cek/index.js";
import { iamChecks } from "./iam/index.js";

/**
 * Every check the scanner ships.
 *
 * Each entry must have a matching row in `docs/control-mapping.md` — that table
 * is the source of truth, and a test asserts the two cannot drift (ADR-0003).
 */
export const allChecks: readonly Check[] = [...iamChecks, ...cekChecks];

export { cekChecks, iamChecks };
