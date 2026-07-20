import { describe, expect, it } from "vitest";
import type { Resource, ResourceModel, Verdict } from "../../src/index.js";
import { REDACTED, redactSensitive } from "../../src/index.js";

/**
 * The report is an artifact people commit and hand to an auditor, so a secret
 * that reaches it has been published. `terraform show -json` of state puts real
 * values in `values` and marks them in `sensitive_values`; these tests pin that
 * the marks are honoured before any renderer sees them.
 */
function resource(address: string, sensitiveAttributes: readonly string[]): Resource {
  return {
    address,
    type: "aws_db_instance",
    name: address.split(".").pop() ?? address,
    provider: "aws",
    attributes: {},
    unknownAttributes: [],
    sensitiveAttributes,
  };
}

function model(...resources: Resource[]): ResourceModel {
  return { source: "memory:redact-test", resources };
}

function verdict(evidence: Verdict["evidence"]): Verdict {
  return {
    ccmId: "CEK-03",
    ccmTitle: "Data Encryption",
    checkId: "cek/encryption-at-rest",
    status: "fail",
    evidence,
  };
}

describe("redactSensitive", () => {
  it("redacts an evidence entry that cites a sensitive attribute", () => {
    const verdicts = [
      verdict([
        { resourceAddress: "aws_db_instance.main", attribute: "password", observed: "hunter2" },
      ]),
    ];
    const [redacted] = redactSensitive(
      verdicts,
      model(resource("aws_db_instance.main", ["password"])),
    );
    expect(redacted?.evidence[0]?.observed).toBe(REDACTED);
  });

  // Terraform marks the top-level attribute, and evidence may cite a path
  // inside it.
  it("redacts a nested path under a sensitive attribute", () => {
    const verdicts = [
      verdict([
        { resourceAddress: "aws_db_instance.main", attribute: "master[0].password", observed: "x" },
      ]),
    ];
    const [redacted] = redactSensitive(
      verdicts,
      model(resource("aws_db_instance.main", ["master"])),
    );
    expect(redacted?.evidence[0]?.observed).toBe(REDACTED);
  });

  // A check that reports several attributes at once must not smuggle one out
  // inside an object.
  it("redacts sensitive keys of an object-valued observation", () => {
    const verdicts = [
      verdict([
        {
          resourceAddress: "aws_db_instance.main",
          attribute: "settings",
          observed: { engine: "postgres", password: "hunter2" },
        },
      ]),
    ];
    const [redacted] = redactSensitive(
      verdicts,
      model(resource("aws_db_instance.main", ["password"])),
    );
    expect(redacted?.evidence[0]?.observed).toEqual({ engine: "postgres", password: REDACTED });
  });

  it("leaves non-sensitive evidence untouched", () => {
    const verdicts = [
      verdict([
        {
          resourceAddress: "aws_db_instance.main",
          attribute: "storage_encrypted",
          observed: false,
        },
      ]),
    ];
    const [redacted] = redactSensitive(
      verdicts,
      model(resource("aws_db_instance.main", ["password"])),
    );
    expect(redacted?.evidence[0]?.observed).toBe(false);
  });

  // Marks are per resource: one resource's secret says nothing about another's
  // attribute of the same name.
  it("does not redact a same-named attribute on a different resource", () => {
    const verdicts = [
      verdict([
        { resourceAddress: "aws_db_instance.other", attribute: "password", observed: "shown" },
      ]),
    ];
    const [redacted] = redactSensitive(
      verdicts,
      model(resource("aws_db_instance.main", ["password"])),
    );
    expect(redacted?.evidence[0]?.observed).toBe("shown");
  });

  it("returns the verdicts unchanged when nothing is marked sensitive", () => {
    const verdicts = [
      verdict([
        { resourceAddress: "aws_db_instance.main", attribute: "password", observed: "shown" },
      ]),
    ];
    expect(redactSensitive(verdicts, model(resource("aws_db_instance.main", [])))).toBe(verdicts);
  });

  it("preserves the rest of the verdict", () => {
    const original = verdict([
      { resourceAddress: "aws_db_instance.main", attribute: "password", observed: "hunter2" },
    ]);
    const [redacted] = redactSensitive(
      [original],
      model(resource("aws_db_instance.main", ["password"])),
    );
    expect(redacted?.ccmId).toBe("CEK-03");
    expect(redacted?.status).toBe("fail");
    expect(redacted?.evidence[0]?.attribute).toBe("password");
  });
});
