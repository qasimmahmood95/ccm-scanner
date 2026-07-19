import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { renderJson, renderSummary } from "../../src/index.js";
import { GOLDEN_JSON, GOLDEN_MD, buildStubReport } from "../support/stubs.js";

const report = buildStubReport();

describe("renderers", () => {
  it("renders JSON matching the golden file", () => {
    expect(renderJson(report)).toBe(readFileSync(GOLDEN_JSON, "utf8"));
  });

  it("renders the Markdown summary matching the golden file", () => {
    expect(renderSummary(report)).toBe(readFileSync(GOLDEN_MD, "utf8"));
  });

  it("is deterministic: the same input renders byte-identically", () => {
    expect(renderJson(buildStubReport())).toBe(renderJson(buildStubReport()));
    expect(renderSummary(buildStubReport())).toBe(renderSummary(buildStubReport()));
  });
});

describe("summary content", () => {
  const summary = renderSummary(report);

  it("leads with the headline verdict and counts", () => {
    expect(summary).toContain("**Result: FAIL**");
    expect(summary).toContain("1 pass, 1 fail, 1 not applicable (3 controls)");
  });

  it("groups by CCM domain", () => {
    expect(summary).toContain("## IVS — Infrastructure & Virtualization Security");
  });

  it("expands a failure with its evidence", () => {
    expect(summary).toContain("### FAIL · IVS-03 Network Security");
    expect(summary).toContain("`aws_security_group.web`");
    expect(summary).toContain("expected: no ingress from 0.0.0.0/0 to an administrative port");
  });

  it("expands a not-applicable with its reason", () => {
    expect(summary).toContain("### N/A · IAM-08 User Access Review");
    expect(summary).toContain("Reason: Periodic access review is a process control");
  });

  it("lists passing controls compactly", () => {
    expect(summary).toContain("- CEK-03 Data Encryption (`cek/encryption-at-rest`)");
  });
});
