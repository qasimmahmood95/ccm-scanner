import { describe, expect, it } from "vitest";
import { fail, notApplicable, pass, type ControlRef, type Evidence } from "../../src/index.js";

const control: ControlRef = {
  ccmId: "IVS-03",
  ccmTitle: "Network Security",
  checkId: "ivs/no-open-admin-ports",
};

const evidence: readonly Evidence[] = [
  { resourceAddress: "aws_security_group.web", observed: "0.0.0.0/0" },
];

describe("pass / fail", () => {
  it("carries the control identity, status and evidence", () => {
    const verdict = pass(control, evidence);
    expect(verdict).toMatchObject({ ...control, status: "pass" });
    expect(verdict.evidence).toHaveLength(1);
  });

  it("omits `reason` entirely rather than setting it to undefined", () => {
    expect("reason" in pass(control, evidence)).toBe(false);
    expect("reason" in fail(control, evidence)).toBe(false);
  });

  it("refuses an unevidenced pass", () => {
    expect(() => pass(control, [])).toThrow(/requires evidence/);
  });

  it("refuses an unevidenced fail", () => {
    expect(() => fail(control, [])).toThrow(/requires evidence/);
  });
});

describe("notApplicable", () => {
  it("requires a reason and carries no evidence", () => {
    const verdict = notApplicable(control, "process control");
    expect(verdict.status).toBe("not_applicable");
    expect(verdict.reason).toBe("process control");
    expect(verdict.evidence).toEqual([]);
  });

  it("refuses a blank reason", () => {
    expect(() => notApplicable(control, "   ")).toThrow(/requires a reason/);
  });
});
