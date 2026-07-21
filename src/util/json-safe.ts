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
const TOO_DEEP = "[too deep]";

/**
 * Depth past which a value is reported as `[too deep]` rather than descended
 * into. Evidence is shallow in practice — a policy statement is a handful of
 * levels — so this never truncates real output; it exists only so a
 * pathological structure cannot reach the ~3,600-level limit at which
 * `JSON.stringify(_, null, 2)` blows the stack. That is the one step
 * `toJsonSafe` cannot itself contain, so it must produce nothing that deep.
 */
const MAX_DEPTH = 200;

export function toJsonSafe(value: unknown): unknown {
  return coerce(value, new Set<object>(), 0);
}

/**
 * Reads a property that may be a hostile getter, coercing the read itself —
 * not just its result — through the safe path.
 *
 * `toJsonSafe(x.observed)` still evaluates `x.observed` at the call site, so a
 * throwing getter escapes before `toJsonSafe` runs. Evidence `observed` is the
 * one `unknown` the report reads raw, in both the comparator and the renderer;
 * routing both through here keeps the documented promise that rendering never
 * throws.
 */
export function toJsonSafeProperty(owner: object, key: string): unknown {
  let raw: unknown;
  try {
    raw = (owner as Record<string, unknown>)[key];
  } catch {
    return UNSERIALISABLE;
  }
  return toJsonSafe(raw);
}

/** `String(x)` can itself throw (null-prototype objects, hostile toPrimitive). */
function safeString(value: unknown): string {
  try {
    return String(value);
  } catch {
    return UNSERIALISABLE;
  }
}

function coerce(value: unknown, seen: Set<object>, depth: number): unknown {
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

  // A cycle is already handled by `seen`; this catches the acyclic-but-vast
  // case, so the output handed to JSON.stringify is bounded in depth.
  if (depth >= MAX_DEPTH) {
    return TOO_DEEP;
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
        return coerce((toJson as (this: unknown) => unknown).call(value), seen, depth + 1);
      } catch {
        return safeString(value);
      }
    }

    if (Array.isArray(value)) {
      return value.map((entry) => coerce(entry, seen, depth + 1));
    }
    if (value instanceof Map) {
      const out: Record<string, unknown> = {};
      let index = 0;
      for (const [key, entry] of value) {
        // Two keys that stringify alike must not collapse into one, or evidence
        // is silently lost.
        const name = safeString(key);
        out[Object.hasOwn(out, name) ? `${name} (${String(index)})` : name] = coerce(
          entry,
          seen,
          depth + 1,
        );
        index += 1;
      }
      return out;
    }
    if (value instanceof Set) {
      return [...value].map((entry) => coerce(entry, seen, depth + 1));
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
        out[key] = coerce((value as Record<string, unknown>)[key], seen, depth + 1);
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
