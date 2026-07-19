import { describe, expect, it } from "vitest";
import {
  fail,
  notApplicable,
  pass,
  verdictOf,
  type ControlRef,
  type Evidence,
} from "../../src/index.js";

const control: ControlRef = {
  ccmId: "IVS-03",
  ccmTitle: "Network Security",
  checkId: "ivs/no-open-admin-ports",
};

const evidence: readonly Evidence[] = [
  { resourceAddress: "aws_security_group.web", observed: "0.0.0.0/0" },
];

describe("finding constructors", () => {
  it("build a status plus its evidence, with no control identity", () => {
    expect(pass(evidence)).toEqual({ status: "pass", evidence });
    expect(fail(evidence)).toEqual({ status: "fail", evidence });
  });

  it("notApplicable carries a reason and no evidence", () => {
    expect(notApplicable("process control")).toEqual({
      status: "not_applicable",
      evidence: [],
      reason: "process control",
    });
  });
});

describe("verdictOf", () => {
  it("stamps the control identity onto the finding", () => {
    expect(verdictOf(control, pass(evidence))).toMatchObject({ ...control, status: "pass" });
  });

  it("omits `reason` entirely rather than setting it to undefined", () => {
    expect("reason" in verdictOf(control, pass(evidence))).toBe(false);
    expect("reason" in verdictOf(control, fail(evidence))).toBe(false);
  });

  it("refuses an unevidenced pass", () => {
    expect(() => verdictOf(control, pass([]))).toThrow(/requires evidence/);
  });

  it("refuses an unevidenced fail", () => {
    expect(() => verdictOf(control, fail([]))).toThrow(/requires evidence/);
  });

  it("refuses a blank not_applicable reason", () => {
    expect(() => verdictOf(control, notApplicable("   "))).toThrow(/requires a reason/);
  });

  it("names the offending control and check in the error", () => {
    expect(() => verdictOf(control, pass([]))).toThrow(/IVS-03 \(ivs\/no-open-admin-ports\)/);
  });
});
