import { describe, expect, it } from "vitest";
import { createRegistry, type Check } from "../../src/index.js";

function check(overrides: Partial<Check> = {}): Check {
  return {
    checkId: "ivs/no-open-admin-ports",
    ccmId: "IVS-03",
    ccmTitle: "Network Security",
    run: () => [],
    ...overrides,
  };
}

describe("createRegistry validation", () => {
  it("accepts a well-formed check", () => {
    expect(createRegistry([check()]).checks).toHaveLength(1);
  });

  it("rejects a checkId that embeds the CCM control number (ADR-0003)", () => {
    expect(() => createRegistry([check({ checkId: "ivs-03/no-open-admin-ports" })])).toThrow(
      /must not embed the CCM/i,
    );
  });

  it("rejects a checkId that is not kebab-case", () => {
    expect(() => createRegistry([check({ checkId: "ivs/No_Open_Ports" })])).toThrow(
      /invalid checkId/,
    );
  });

  it("rejects a malformed ccmId", () => {
    expect(() => createRegistry([check({ ccmId: "IVS-3" })])).toThrow(/invalid ccmId/);
  });

  it("rejects a domain mismatch between checkId and ccmId", () => {
    expect(() => createRegistry([check({ checkId: "iam/no-open-admin-ports" })])).toThrow(
      /namespaced to IAM but its control IVS-03 belongs to IVS/,
    );
  });

  it("rejects a blank CCM title", () => {
    expect(() => createRegistry([check({ ccmTitle: "  " })])).toThrow(/verbatim CCM title/);
  });

  it("rejects duplicate check ids", () => {
    expect(() => createRegistry([check(), check()])).toThrow(/duplicate checkId/);
  });
});

describe("selection", () => {
  const registry = createRegistry([
    check(),
    check({ checkId: "iam/least-privilege", ccmId: "IAM-05", ccmTitle: "Least Privilege" }),
    check({ checkId: "cek/key-rotation", ccmId: "CEK-12", ccmTitle: "Key Rotation" }),
  ]);

  it("orders checks by ccmId then checkId", () => {
    expect(registry.checks.map((entry) => entry.ccmId)).toEqual(["CEK-12", "IAM-05", "IVS-03"]);
  });

  it("selects everything by default", () => {
    expect(registry.select()).toHaveLength(3);
  });

  it("selects by domain", () => {
    expect(registry.select({ domains: ["IAM"] }).map((entry) => entry.ccmId)).toEqual(["IAM-05"]);
  });

  it("selects by ccmId", () => {
    expect(registry.select({ ccmIds: ["CEK-12"] }).map((entry) => entry.checkId)).toEqual([
      "cek/key-rotation",
    ]);
  });

  // A silently-empty selection would exit 0 and print PASS, which is worse than
  // an error: the operator would believe a control was assessed when it wasn't.
  it("rejects a domain with no registered checks", () => {
    expect(() => registry.select({ domains: ["LOG"] })).toThrow(
      /no registered checks for domain\(s\): LOG/,
    );
  });

  it("rejects a control id with no registered check", () => {
    expect(() => registry.select({ ccmIds: ["IAM-99"] })).toThrow(
      /no registered checks for control\(s\): IAM-99/,
    );
  });

  it("rejects a selector combination that matches nothing", () => {
    expect(() => registry.select({ domains: ["IAM"], ccmIds: ["CEK-12"] })).toThrow(
      /matched no registered checks/,
    );
  });

  it("rejects an empty domain list rather than selecting nothing", () => {
    expect(() => registry.select({ domains: [] })).toThrow(/matched no registered checks/);
  });
});
