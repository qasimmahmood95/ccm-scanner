import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  buildReport,
  createRegistry,
  evaluate,
  fail,
  notApplicable,
  pass,
  renderJson,
  renderSummary,
  verdictOf,
  type Check,
  type ControlRef,
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

const IVS_03: ControlRef = {
  ccmId: "IVS-03",
  ccmTitle: "Network Security",
  checkId: "ivs/no-open-admin-ports",
};

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

  it("notes explicitly when nothing was evaluated", () => {
    expect(renderSummary(buildReport([], fixedMetadata))).toContain(
      "_No controls were evaluated._",
    );
  });
});

// docs/control-mapping.md already defines two checks for CEK-03, so a passing
// control must not report one check's id against every check's findings.
describe("a passing control with more than one check", () => {
  const encryption: Check = {
    checkId: "cek/encryption-at-rest",
    ccmId: "CEK-03",
    ccmTitle: "Data Encryption",
    run: () => [
      pass([{ resourceAddress: "aws_s3_bucket.a", observed: "aws:kms" }]),
      pass([{ resourceAddress: "aws_s3_bucket.b", observed: "aws:kms" }]),
    ],
  };
  const tls: Check = {
    checkId: "cek/tls-enforced",
    ccmId: "CEK-03",
    ccmTitle: "Data Encryption",
    run: () => [notApplicable("no bucket policies are declared in this input")],
  };
  const summary = renderSummary(
    buildReport(evaluate(createRegistry([encryption, tls]).select(), stubModel), fixedMetadata),
  );

  it("attributes findings to the check that produced them", () => {
    expect(summary).toContain("`cek/encryption-at-rest` — 2 findings (pass)");
  });

  it("still surfaces a not-applicable check inside an otherwise passing control", () => {
    expect(summary).toContain(
      "`cek/tls-enforced` — not applicable: no bucket policies are declared in this input",
    );
  });
});

describe("untrusted values from scanned infrastructure", () => {
  it("widens the code fence so a backtick cannot break out", () => {
    const verdict = verdictOf(IVS_03, fail([{ resourceAddress: "aws_sg.a`b", observed: "x|y" }]));
    expect(renderSummary(buildReport([verdict], fixedMetadata))).toContain("``aws_sg.a`b``");
  });

  // A resource address is arbitrary text (a for_each key, a tag). Left raw, a
  // newline lets it forge document structure inside the audit deliverable.
  it("cannot forge a heading via newlines in a resource address", () => {
    const forged = "aws_s3_bucket.b\n\n### PASS · IVS-03 Network Security\n\nNo issues found.";
    const verdict = verdictOf(IVS_03, fail([{ resourceAddress: forged, observed: true }]));
    const summary = renderSummary(buildReport([verdict], fixedMetadata));

    expect(summary).not.toMatch(/^### PASS/m);
    expect(summary.match(/^### /gm)).toHaveLength(1);
  });

  it("cannot forge structure via newlines in a reason or expectation", () => {
    const verdict = verdictOf(IVS_03, notApplicable("line one\n\n### PASS · forged\n"));
    const summary = renderSummary(buildReport([verdict], fixedMetadata));
    expect(summary).not.toMatch(/^### PASS/m);
  });

  // CommonMark treats a lone CR as a line ending, so matching /\r?\n/ was not
  // enough: a CR-only payload still forged headings and opened HTML blocks.
  it("cannot forge a heading via a lone carriage return", () => {
    const cr = String.fromCharCode(13);
    const forged = `aws_s3_bucket.b${cr}${cr}### PASS · IVS-03 Network Security${cr}${cr}No issues found.`;
    const verdict = verdictOf(IVS_03, fail([{ resourceAddress: forged, observed: true }]));
    const summary = renderSummary(buildReport([verdict], fixedMetadata));

    expect(summary).not.toMatch(/^### PASS/m);
    expect(summary.split("\n").filter((line) => line.startsWith("### "))).toHaveLength(1);
  });

  it("cannot hide a real failure behind an unterminated HTML comment", () => {
    const cr = String.fromCharCode(13);
    const verdict = verdictOf(IVS_03, notApplicable(`no signal${cr}${cr}<!-- `));
    const summary = renderSummary(buildReport([verdict], fixedMetadata));
    expect(summary).not.toMatch(/^<!--/m);
  });

  it("neutralises U+2028 and U+2029 line separators", () => {
    const ls = String.fromCharCode(0x2028);
    const ps = String.fromCharCode(0x2029);
    const verdict = verdictOf(IVS_03, fail([{ resourceAddress: `a${ls}b${ps}c`, observed: true }]));
    const summary = renderSummary(buildReport([verdict], fixedMetadata));

    expect(summary).not.toContain(ls);
    expect(summary).not.toContain(ps);
  });

  // A <details> or hidden <div> in a reason would make every following section
  // a collapsed/invisible descendant of it.
  it("neutralises inline HTML in a reason", () => {
    const verdict = verdictOf(IVS_03, notApplicable('<div style="display:none">swallow'));
    const summary = renderSummary(buildReport([verdict], fixedMetadata));

    expect(summary).not.toContain("<div");
    expect(summary).toContain("&lt;div");
  });

  it("keeps the metadata table intact when a field contains a carriage return", () => {
    const cr = String.fromCharCode(13);
    const summary = renderSummary(
      buildReport([], {
        ...fixedMetadata,
        tool: { name: `ccm${cr}${cr}| forged |`, version: "1" },
      }),
    );
    // header + separator + five data rows, and nothing extra
    expect(summary.split("\n").filter((line) => line.startsWith("|"))).toHaveLength(7);
  });
});

// One check routinely emits several findings for one resource — one per ingress
// rule, say — which tie on control, check, address and status. Array.sort is
// stable, so without a final discriminator the input order leaks into the bytes.
describe("verdicts that tie on the primary sort keys", () => {
  function ruleVerdict(attribute: string) {
    return verdictOf(
      IVS_03,
      fail([{ resourceAddress: "aws_security_group.web", attribute, observed: true }]),
    );
  }
  const ordered = [ruleVerdict("ingress[0]"), ruleVerdict("ingress[1]")];
  const shuffled = [...ordered].reverse();

  // An absent attribute is omitted by the JSON renderer; anything that made it
  // compare equal to a present one would let input order leak into the bytes.
  it("distinguishes an absent attribute from a present one", () => {
    const withAttribute = verdictOf(
      IVS_03,
      fail([{ resourceAddress: "aws_security_group.web", attribute: "ingress", observed: true }]),
    );
    const withoutAttribute = verdictOf(
      IVS_03,
      fail([{ resourceAddress: "aws_security_group.web", observed: true }]),
    );
    const forward = [withAttribute, withoutAttribute];
    const backward = [withoutAttribute, withAttribute];

    expect(renderJson(buildReport(backward, fixedMetadata))).toBe(
      renderJson(buildReport(forward, fixedMetadata)),
    );
  });

  it("renders byte-identically whichever order they arrive in", () => {
    expect(renderJson(buildReport(shuffled, fixedMetadata))).toBe(
      renderJson(buildReport(ordered, fixedMetadata)),
    );
    expect(renderSummary(buildReport(shuffled, fixedMetadata))).toBe(
      renderSummary(buildReport(ordered, fixedMetadata)),
    );
  });
});

describe("non-JSON observed values", () => {
  it("coerces a BigInt rather than throwing or dropping the field", () => {
    const verdict = verdictOf(IVS_03, fail([{ resourceAddress: "aws_sg.a", observed: 10n }]));
    expect(renderJson(buildReport([verdict], fixedMetadata))).toContain('"observed": "10"');
  });

  // The cloud-snapshot lane surfaces SDK Date values; recording them as {} would
  // destroy exactly the evidence LOG/IAM/CEK controls rest on.
  it("preserves a Date as an ISO string", () => {
    const verdict = verdictOf(
      IVS_03,
      fail([{ resourceAddress: "aws_sg.a", observed: new Date(0) }]),
    );
    expect(renderJson(buildReport([verdict], fixedMetadata))).toContain(
      '"observed": "1970-01-01T00:00:00.000Z"',
    );
  });
});

describe("input warnings in the summary", () => {
  // A scan that silently dropped part of its input otherwise produces a
  // clean-looking report over something it never read.
  it("lists them, above the results", () => {
    const md = renderSummary(buildStubReport(["dropped module.a", "ambiguous <shape>"]));
    expect(md).toContain("## Input warnings");
    expect(md).toContain("- dropped module.a");
    expect(md.indexOf("## Input warnings")).toBeLessThan(md.indexOf("## Coverage by domain"));
  });

  // Warnings quote resource addresses and raw input, so they are untrusted.
  it("escapes warning text rather than letting it forge structure", () => {
    const md = renderSummary(buildStubReport(["ambiguous <shape>", "line\nbreak"]));
    expect(md).toContain("&lt;shape>");
    expect(md).not.toContain("<shape>");
    // A newline would end the list item and let the rest render as Markdown.
    expect(md).toContain("- line break");
  });

  it("omits the section entirely when there are none", () => {
    expect(renderSummary(buildStubReport())).not.toContain("## Input warnings");
  });
});
