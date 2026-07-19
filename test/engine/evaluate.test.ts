import { describe, expect, it } from "vitest";
import { createRegistry, evaluate } from "../../src/index.js";
import { stubChecks, stubModel } from "../support/stubs.js";

describe("evaluate", () => {
  it("orders verdicts by ccmId regardless of check registration order", () => {
    const forward = evaluate(createRegistry(stubChecks).select(), stubModel);
    const reversed = evaluate(createRegistry([...stubChecks].reverse()).select(), stubModel);

    expect(forward.map((verdict) => verdict.ccmId)).toEqual(["CEK-03", "IAM-08", "IVS-03"]);
    expect(reversed).toEqual(forward);
  });

  it("returns nothing when no checks are selected", () => {
    expect(evaluate([], stubModel)).toEqual([]);
  });
});
