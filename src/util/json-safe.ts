/**
 * Coerces an arbitrary value into something `JSON.stringify` can always render.
 *
 * Evidence `observed` values come from parsed input and are normally plain
 * JSON, but the cloud-snapshot lane surfaces SDK values such as `Date` (IAM
 * CreateDate, KMS rotation dates) and a check could hand us a BigInt, a
 * function, a non-finite number or a cyclic object. Rendering the report must
 * never throw, never silently drop a field the schema requires, and never
 * flatten a real timestamp to `{}` — so we coerce deliberately rather than trust.
 */
export function toJsonSafe(value: unknown): unknown {
  return coerce(value, new Set<object>());
}

function coerce(value: unknown, seen: Set<object>): unknown {
  if (value === null) {
    return null;
  }
  if (typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : String(value);
  }
  if (typeof value === "bigint") {
    return value.toString();
  }
  // undefined, function, symbol have no JSON representation.
  if (typeof value !== "object") {
    return null;
  }

  if (seen.has(value)) {
    return "[circular]";
  }
  seen.add(value);
  try {
    // Honour the toJSON contract first: this is what preserves Date as an ISO
    // string rather than serialising it as an empty object.
    const toJson: unknown = (value as { toJSON?: unknown }).toJSON;
    if (typeof toJson === "function") {
      try {
        return coerce((toJson as (this: unknown) => unknown).call(value), seen);
      } catch {
        return String(value);
      }
    }
    if (Array.isArray(value)) {
      return value.map((entry) => coerce(entry, seen));
    }
    if (value instanceof Map) {
      const out: Record<string, unknown> = {};
      for (const [key, entry] of value) {
        out[String(key)] = coerce(entry, seen);
      }
      return out;
    }
    if (value instanceof Set) {
      return [...value].map((entry) => coerce(entry, seen));
    }
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      out[key] = coerce(entry, seen);
    }
    return out;
  } finally {
    seen.delete(value);
  }
}
