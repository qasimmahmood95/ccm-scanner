import { describe, expect, it } from "vitest";
import {
  buildReport,
  createRegistry,
  evaluate,
  fail,
  notApplicable,
  verdictOf,
  type ControlRef,
} from "../../src/index.js";
import { fixedMetadata, stubChecks, stubModel } from "../support/stubs.js";

const report = buildReport(evaluate(createRegistry(stubChecks).select(), stubModel), fixedMetadata);

describe("controls vs findings", () => {
  // Three controls, but four findings: CEK-03 is assessed against two buckets.
  // Conflating these would overstate how many controls were assessed.
  it("counts distinct controls by their rolled-up status", () => {
    expect(report.controls).toEqual({ pass: 1, fail: 1, notApplicable: 1, total: 3 });
  });

  it("counts findings separately from controls", () => {
    expect(report.findings).toEqual({ pass: 2, fail: 1, notApplicable: 1, total: 4 });
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
    const clean = buildReport([verdictOf(control, notApplicable("process"))], fixedMetadata);
    expect(clean.headline).toBe("pass");
  });
});

describe("domain roll-ups", () => {
  it("uses canonical domain order and omits domains with no verdicts", () => {
    expect(report.domains.map((rollup) => rollup.domain)).toEqual(["IAM", "CEK", "IVS"]);
  });

  it("separates control and finding counts within a domain", () => {
    expect(report.domains).toContainEqual({
      domain: "CEK",
      controls: { pass: 1, fail: 0, notApplicable: 0, total: 1 },
      findings: { pass: 2, fail: 0, notApplicable: 0, total: 2 },
    });
  });

  // If a verdict were ever dropped from the per-domain view it would still be
  // counted in the totals, producing a headline with no supporting detail.
  it("reconciles: domain totals sum to the overall totals", () => {
    const controls = report.domains.reduce((sum, rollup) => sum + rollup.controls.total, 0);
    const findings = report.domains.reduce((sum, rollup) => sum + rollup.findings.total, 0);
    expect(controls).toBe(report.controls.total);
    expect(findings).toBe(report.findings.total);
  });

  it("refuses a verdict whose control is outside the in-scope domains", () => {
    const rogue = verdictOf(
      { ccmId: "TVM-01", ccmTitle: "Out of scope", checkId: "iam/rogue" },
      fail([{ resourceAddress: "aws_thing.x", observed: true }]),
    );
    expect(() => buildReport([rogue], fixedMetadata)).toThrow(/not an in-scope CCM control id/);
  });
});

describe("metadata validation", () => {
  it("echoes valid metadata verbatim", () => {
    expect(report.metadata).toEqual(fixedMetadata);
    expect(report.schemaVersion).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("rejects a digest that is not a sha256 hex string", () => {
    const metadata = {
      ...fixedMetadata,
      input: { ...fixedMetadata.input, digest: "NOT-A-DIGEST" },
    };
    expect(() => buildReport([], metadata)).toThrow(/digest/);
  });

  it("rejects a timestamp that is not ISO-8601 with a timezone", () => {
    expect(() => buildReport([], { ...fixedMetadata, generatedAt: "2026-07-19 12:00:00" })).toThrow(
      /generatedAt/,
    );
  });

  it("rejects empty tool identification", () => {
    expect(() =>
      buildReport([], { ...fixedMetadata, tool: { name: "  ", version: "1.0.0" } }),
    ).toThrow(/tool\.name/);
  });
});
