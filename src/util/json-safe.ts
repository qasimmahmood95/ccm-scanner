/**
 * Coerces an arbitrary value into something `JSON.stringify` can always render.
 *
 * Evidence `observed` values come from parsed input and are normally plain
 * JSON, but the cloud-snapshot lane surfaces SDK values such as `Date` (IAM
 * CreateDate, KMS rotation dates) and a check could hand us a BigInt, a
 * function, a non-finite number, a cyclic object, or something actively
 * hostile like a throwing getter. Rendering the report must never throw and
 * never silently drop a field the schema requires, so every step that can
 * fail is contained.
 */
const UNSERIALISABLE = "[unserialisable]";

export function toJsonSafe(value: unknown): unknown {
  return coerce(value, new Set<object>());
}

/** `String(x)` can itself throw (null-prototype objects, hostile toPrimitive). */
function safeString(value: unknown): string {
  try {
    return String(value);
  } catch {
    return UNSERIALISABLE;
  }
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
    let toJson: unknown;
    try {
      toJson = (value as { toJSON?: unknown }).toJSON;
    } catch {
      toJson = undefined;
    }
    if (typeof toJson === "function") {
      try {
        return coerce((toJson as (this: unknown) => unknown).call(value), seen);
      } catch {
        return safeString(value);
      }
    }

    if (Array.isArray(value)) {
      return value.map((entry) => coerce(entry, seen));
    }
    if (value instanceof Map) {
      const out: Record<string, unknown> = {};
      let index = 0;
      for (const [key, entry] of value) {
        // Two keys that stringify alike must not collapse into one, or evidence
        // is silently lost.
        const name = safeString(key);
        out[Object.hasOwn(out, name) ? `${name} (${String(index)})` : name] = coerce(entry, seen);
        index += 1;
      }
      return out;
    }
    if (value instanceof Set) {
      return [...value].map((entry) => coerce(entry, seen));
    }

    const out: Record<string, unknown> = {};
    let keys: string[];
    try {
      keys = Object.keys(value);
    } catch {
      return UNSERIALISABLE;
    }
    for (const key of keys) {
      // One hostile getter must not take down the whole report.
      try {
        out[key] = coerce((value as Record<string, unknown>)[key], seen);
      } catch {
        out[key] = UNSERIALISABLE;
      }
    }
    return out;
  } catch {
    // Backstop: a revoked Proxy throws even on Array.isArray and instanceof.
    return UNSERIALISABLE;
  } finally {
    seen.delete(value);
  }
}
