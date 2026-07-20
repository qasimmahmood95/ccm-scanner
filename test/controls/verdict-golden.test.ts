import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { allChecks } from "../../src/controls/index.js";
import { FIXTURES, goldenPath, renderVerdicts } from "../support/fixture-verdicts.js";

/**
 * Golden files over the *real* checks' output, evidence and reasons included.
 *
 * `fixtures.test.ts` asserts which controls pass and fail. That catches a wrong
 * verdict but not a wrong *justification*, and several defects in this project
 * were exactly that: a Pass citing evidence the input never supplied, a
 * resource described as something it is not, a reason naming the wrong
 * attribute or the wrong cause. Those are defects in the deliverable, so they
 * get pinned like any other output.
 *
 * Run `npm run goldens:update` after an intentional change, then read the diff.
 */
describe("fixture verdict goldens", () => {
  for (const fixture of FIXTURES) {
    it(`matches the recorded output for ${fixture}`, () => {
      const golden = readFileSync(goldenPath(fixture), "utf8");
      expect(renderVerdicts(fixture)).toBe(golden);
    });
  }

  // A golden only guards what it contains, so what it contains is asserted
  // rather than assumed: a check missing from both fixtures is a check whose
  // output nothing pins.
  it("covers every registered check in at least one fixture", () => {
    const rendered = FIXTURES.map((fixture) => renderVerdicts(fixture)).join("\n");
    const missing = allChecks
      .map((check) => check.checkId)
      .filter((checkId) => !rendered.includes(checkId));
    expect(missing).toEqual([]);
  });
});
