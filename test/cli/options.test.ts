import { describe, expect, it } from "vitest";
import {
  parseControls,
  parseFailOn,
  parseFormat,
  UsageError,
  validateDestination,
} from "../../src/cli/options.js";

/**
 * A mistyped selector must never quietly narrow a scan. A report that assessed
 * three controls instead of thirteen still says "PASS", so every one of these
 * is a correctness test, not an ergonomics test.
 */
describe("parseControls", () => {
  it("accepts all", () => {
    expect(parseControls("all")).toEqual({ kind: "all" });
    expect(parseControls("ALL")).toEqual({ kind: "all" });
  });

  it("accepts domains case-insensitively", () => {
    expect(parseControls("iam,CEK")).toEqual({ kind: "some", domains: ["IAM", "CEK"], ccmIds: [] });
  });

  it("accepts control ids and normalises their case", () => {
    expect(parseControls("iam-05,CEK-12")).toEqual({
      kind: "some",
      domains: [],
      ccmIds: ["IAM-05", "CEK-12"],
    });
  });

  it("accepts a mix of domains and control ids", () => {
    expect(parseControls("iam,CEK-12")).toEqual({
      kind: "some",
      domains: ["IAM"],
      ccmIds: ["CEK-12"],
    });
  });

  it("tolerates whitespace and empty segments", () => {
    expect(parseControls(" iam , , log ")).toEqual({
      kind: "some",
      domains: ["IAM", "LOG"],
      ccmIds: [],
    });
  });

  // The failure mode this guards: a typo silently selecting nothing, or
  // selecting less than the user believes, and the report still reading PASS.
  it("rejects an unrecognised token, naming it", () => {
    expect(() => parseControls("iam,nope")).toThrow(UsageError);
    expect(() => parseControls("iam,nope")).toThrow(/nope/);
  });

  it("rejects an empty selector", () => {
    expect(() => parseControls("   ")).toThrow(UsageError);
  });

  // Silently ignoring the rest would be defensible; saying so is better than
  // letting someone believe they narrowed a scan they did not narrow.
  it("rejects all combined with other selectors", () => {
    expect(() => parseControls("all,iam")).toThrow(/already selects everything/);
  });

  it("rejects something that merely looks like a control id", () => {
    expect(() => parseControls("IAM-")).toThrow(UsageError);
    expect(() => parseControls("-05")).toThrow(UsageError);
  });
});

describe("parseFormat and parseFailOn", () => {
  it("accept their documented values", () => {
    expect(parseFormat("json")).toBe("json");
    expect(parseFormat("md")).toBe("md");
    expect(parseFormat("both")).toBe("both");
    expect(parseFailOn("fail")).toBe("fail");
    expect(parseFailOn("none")).toBe("none");
  });

  it("reject anything else, echoing what was given", () => {
    expect(() => parseFormat("xml")).toThrow(/got "xml"/);
    expect(() => parseFailOn("always")).toThrow(/got "always"/);
    // Case matters: silently accepting JSON would invite silently accepting
    // things that are not formats at all.
    expect(() => parseFormat("JSON")).toThrow(UsageError);
  });
});

describe("validateDestination", () => {
  it("allows a single format on stdout", () => {
    expect(() => {
      validateDestination("json", undefined);
    }).not.toThrow();
  });

  // Two documents cannot share one stdout without a delimiter that corrupts
  // both, so this is a usage error rather than an invented convention.
  it("requires --out for both", () => {
    expect(() => {
      validateDestination("both", undefined);
    }).toThrow(/needs --out/);
    expect(() => {
      validateDestination("both", "./out");
    }).not.toThrow();
  });
});
