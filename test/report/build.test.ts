import { describe, expect, it } from "vitest";
import {
  buildReport,
  createRegistry,
  evaluate,
  notApplicable,
  type ControlRef,
} from "../../src/index.js";
import { fixedMetadata, stubChecks, stubModel } from "../support/stubs.js";

const report = buildReport(evaluate(createRegistry(stubChecks).select(), stubModel), fixedMetadata);

describe("buildReport", () => {
  it("counts totals across all verdicts", () => {
    expect(report.totals).toEqual({ pass: 1, fail: 1, notApplicable: 1, total: 3 });
  });

  it("headlines fail when any control fails", () => {
    expect(report.headline).toBe("fail");
  });

  it("headlines pass when there are only passes and not-applicables", () => {
    const control: ControlRef = {
      ccmId: "IAM-08",
      ccmTitle: "User Access Review",
      checkId: "iam/na-process-control",
    };
    const clean = buildReport([notApplicable(control, "process control")], fixedMetadata);
    expect(clean.headline).toBe("pass");
  });

  it("rolls up per domain in canonical order, omitting domains with no verdicts", () => {
    expect(report.domains.map((rollup) => rollup.domain)).toEqual(["IAM", "CEK", "IVS"]);
  });

  it("rolls up counts within a domain", () => {
    expect(report.domains).toContainEqual({
      domain: "IVS",
      pass: 0,
      fail: 1,
      notApplicable: 0,
      total: 1,
    });
  });

  it("echoes the injected metadata verbatim", () => {
    expect(report.metadata).toEqual(fixedMetadata);
    expect(report.schemaVersion).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
