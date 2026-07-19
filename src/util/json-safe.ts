/**
 * Coerces an arbitrary value into something `JSON.stringify` can always render.
 *
 * Evidence `observed` values come from parsed input and are normally plain
 * JSON, but a check could hand us a BigInt, a function, a non-finite number or
 * a cyclic object. Rendering the report must never throw, and must never
 * silently drop a field the schema requires — so we coerce rather than trust.
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
    if (Array.isArray(value)) {
      return value.map((entry) => coerce(entry, seen));
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
