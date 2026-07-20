import { describe, expect, it } from "vitest";
import { createRegistry, evaluate, pass, type Check, type Finding } from "../../src/index.js";
import { stubChecks, stubModel } from "../support/stubs.js";

/** Checks must go through the registry before they can be evaluated. */
function validated(checks: readonly Check[]) {
  return createRegistry(checks).select();
}

describe("evaluate", () => {
  it("orders verdicts by ccmId regardless of check registration order", () => {
    const forward = evaluate(validated(stubChecks), stubModel);
    const reversed = evaluate(validated([...stubChecks].reverse()), stubModel);

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
    const [verdict] = evaluate(validated([check]), stubModel);
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
    expect(() => evaluate(validated([boom]), stubModel)).toThrow(
      /check "iam\/boom" \(IAM-05\) failed/,
    );
  });

  it("names the check when it returns something that is not an array", () => {
    const wrong: Check = {
      checkId: "iam/wrong",
      ccmId: "IAM-05",
      ccmTitle: "Least Privilege",
      run: () => undefined as unknown as readonly Finding[],
    };
    expect(() => evaluate(validated([wrong]), stubModel)).toThrow(/check "iam\/wrong"/);
  });
});
