/**
 * Narrowing helpers for untyped JSON.
 *
 * Ingest adapters are the only place that touches raw external input, so the
 * unknown-to-typed narrowing is concentrated here rather than leaking `any`
 * into the model.
 */

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asArray(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? (value as readonly unknown[]) : [];
}

export function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}
