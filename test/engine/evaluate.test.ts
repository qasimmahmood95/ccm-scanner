import { describe, expect, it } from "vitest";
import { createRegistry, evaluate, pass, type Check } from "../../src/index.js";
import { stubChecks, stubModel } from "../support/stubs.js";

describe("evaluate", () => {
  it("orders verdicts by ccmId regardless of check registration order", () => {
    const forward = evaluate(createRegistry(stubChecks).select(), stubModel);
    const reversed = evaluate(createRegistry([...stubChecks].reverse()).select(), stubModel);

    expect(forward.map((verdict) => verdict.ccmId)).toEqual([
      "CEK-03",
      "CEK-03",
      "IAM-08",
      "IVS-03",
    ]);
    expect(reversed).toEqual(forward);
  });

  it("returns nothing when no checks are selected", () => {
    expect(evaluate([], stubModel)).toEqual([]);
  });

  // The control identity is stamped by the engine, so a check physically cannot
  // attribute its result to a different control (ADR-0003).
  it("stamps the registered control identity onto every verdict", () => {
    const check: Check = {
      checkId: "iam/least-privilege",
      ccmId: "IAM-05",
      ccmTitle: "Least Privilege",
      run: () => [pass([{ resourceAddress: "aws_iam_policy.x", observed: true }])],
    };
    const [verdict] = evaluate([check], stubModel);
    expect(verdict).toMatchObject({
      ccmId: "IAM-05",
      ccmTitle: "Least Privilege",
      checkId: "iam/least-privilege",
    });
  });

  it("names the check that threw instead of failing anonymously", () => {
    const boom: Check = {
      checkId: "iam/boom",
      ccmId: "IAM-05",
      ccmTitle: "Least Privilege",
      run: () => {
        throw new Error("kaboom");
      },
    };
    expect(() => evaluate([boom], stubModel)).toThrow(/check "iam\/boom" \(IAM-05\) threw/);
  });
});
