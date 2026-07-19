import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  buildReport,
  createRegistry,
  evaluate,
  fail,
  renderJson,
  renderSummary,
  verdictOf,
} from "../../src/index.js";
import {
  GOLDEN_JSON,
  GOLDEN_MD,
  buildStubReport,
  fixedMetadata,
  stubChecks,
  stubModel,
} from "../support/stubs.js";

const report = buildStubReport();

describe("golden files", () => {
  it("renders JSON matching the golden file", () => {
    expect(renderJson(report)).toBe(readFileSync(GOLDEN_JSON, "utf8"));
  });

  it("renders the Markdown summary matching the golden file", () => {
    expect(renderSummary(report)).toBe(readFileSync(GOLDEN_MD, "utf8"));
  });

  it("keeps golden files free of CR, so byte comparison survives Windows", () => {
    expect(readFileSync(GOLDEN_JSON, "utf8")).not.toContain("\r");
    expect(readFileSync(GOLDEN_MD, "utf8")).not.toContain("\r");
  });
});

describe("determinism", () => {
  // Rendering twice in one process proves little; rendering from a different
  // registration order is what actually exercises the ordering guarantees.
  it("renders identically regardless of check registration order", () => {
    const forward = buildReport(
      evaluate(createRegistry(stubChecks).select(), stubModel),
      fixedMetadata,
    );
    const reversed = buildReport(
      evaluate(createRegistry([...stubChecks].reverse()).select(), stubModel),
      fixedMetadata,
    );
    expect(renderJson(reversed)).toBe(renderJson(forward));
    expect(renderSummary(reversed)).toBe(renderSummary(forward));
  });
});

describe("summary content", () => {
  const summary = renderSummary(report);

  it("distinguishes controls from findings in the headline", () => {
    expect(summary).toContain("**Result: FAIL**");
    expect(summary).toContain(
      "3 controls assessed: 1 pass, 1 fail, 1 not applicable (from 4 findings)",
    );
  });

  it("groups by CCM domain", () => {
    expect(summary).toContain("## IVS — Infrastructure & Virtualization Security");
  });

  it("expands a failing control with its evidence", () => {
    expect(summary).toContain("### FAIL · IVS-03 Network Security");
    expect(summary).toContain("aws_security_group.web");
    expect(summary).toContain("expected: no ingress from 0.0.0.0/0 to an administrative port");
  });

  it("expands a not-applicable control with its reason", () => {
    expect(summary).toContain("### N/A · IAM-08 User Access Review");
    expect(summary).toContain("Reason: Periodic access review is a process control");
  });

  it("lists a passing control once, with its finding count", () => {
    expect(summary).toContain("- CEK-03 Data Encryption (`cek/encryption-at-rest`) — 2 findings");
  });

  it("notes explicitly when nothing was evaluated", () => {
    expect(renderSummary(buildReport([], fixedMetadata))).toContain(
      "_No controls were evaluated._",
    );
  });
});

describe("untrusted values from scanned infrastructure", () => {
  const verdict = verdictOf(
    { ccmId: "IVS-03", ccmTitle: "Network Security", checkId: "ivs/no-open-admin-ports" },
    fail([{ resourceAddress: "aws_sg.a`b", observed: "x|y" }]),
  );
  const summary = renderSummary(buildReport([verdict], fixedMetadata));

  it("widens the code fence so a backtick cannot break out", () => {
    expect(summary).toContain("``aws_sg.a`b``");
  });

  it("renders a value containing a pipe without breaking the layout", () => {
    expect(summary).toContain('"x|y"');
  });
});

describe("non-JSON observed values", () => {
  it("coerces rather than throwing or dropping the required field", () => {
    const verdict = verdictOf(
      { ccmId: "CEK-12", ccmTitle: "Key Rotation", checkId: "cek/kms-key-rotation" },
      fail([{ resourceAddress: "aws_kms_key.k", observed: 10n }]),
    );
    const json = renderJson(buildReport([verdict], fixedMetadata));
    expect(json).toContain('"observed": "10"');
  });
});
