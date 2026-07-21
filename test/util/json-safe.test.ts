import { describe, expect, it } from "vitest";
import { toJsonSafe, toJsonSafeProperty } from "../../src/util/json-safe.js";

/**
 * `toJsonSafe` is the containment layer between arbitrary `observed` values and
 * a report that must never throw when it renders. Most of its behaviour is
 * exercised through the report tests; these pin the two properties that are
 * hard to reach that way — the depth bound, and reading a value that throws on
 * access rather than on serialisation.
 */
describe("toJsonSafe depth bound", () => {
  function nest(depth: number): unknown {
    let value: unknown = "leaf";
    for (let i = 0; i < depth; i += 1) {
      value = { next: value };
    }
    return value;
  }

  it("passes ordinary evidence depth through untouched", () => {
    const shallow = { a: { b: { c: [1, 2, { d: true }] } } };
    expect(toJsonSafe(shallow)).toEqual(shallow);
  });

  // The one step toJsonSafe cannot contain is the indented JSON.stringify the
  // renderer runs, which blows the stack around 3,600 levels. So the coerced
  // value must never be that deep, whatever it was handed.
  it("bounds a pathologically deep value and stays renderable", () => {
    const coerced = toJsonSafe(nest(50_000));
    expect(() => JSON.stringify(coerced, null, 2)).not.toThrow();
    expect(JSON.stringify(coerced)).toContain("[too deep]");
  });

  it("bounds a deep array the same way", () => {
    let value: unknown = "leaf";
    for (let i = 0; i < 50_000; i += 1) {
      value = [value];
    }
    expect(() => JSON.stringify(toJsonSafe(value), null, 2)).not.toThrow();
  });
});

describe("toJsonSafeProperty", () => {
  it("reads an ordinary property", () => {
    expect(toJsonSafeProperty({ observed: { port: 22 } }, "observed")).toEqual({ port: 22 });
  });

  // The reason the helper exists: `toJsonSafe(x.observed)` evaluates x.observed
  // at the call site, so a throwing getter escapes before toJsonSafe runs.
  it("contains a getter that throws on access", () => {
    const hostile = {
      get observed() {
        throw new Error("boom");
      },
    };
    expect(toJsonSafeProperty(hostile, "observed")).toBe("[unserialisable]");
  });

  it("contains a getter whose value is itself hostile", () => {
    const hostile = {
      get observed() {
        return {
          get inner() {
            throw new Error("boom");
          },
        };
      },
    };
    expect(toJsonSafeProperty(hostile, "observed")).toEqual({ inner: "[unserialisable]" });
  });
});
