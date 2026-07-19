import { readFileSync } from "node:fs";
import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";
import { toJsonObject } from "../../src/index.js";
import { buildStubReport } from "../support/stubs.js";

const schema = JSON.parse(
  readFileSync(new URL("../../schemas/report.schema.json", import.meta.url), "utf8"),
) as object;

// `strictRequired` is an ajv-specific lint that objects to `required` appearing
// inside an `if`/`then` branch. That pattern is idiomatic JSON Schema and the
// properties are declared on the parent verdict schema, so the published schema
// stays clean and we disable just that one check.
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
const validate = ajv.compile(schema);

/** A JSON round-tripped copy so each test can mutate it freely. */
function reportDocument(): Record<string, unknown> {
  return JSON.parse(JSON.stringify(toJsonObject(buildStubReport()))) as Record<string, unknown>;
}

function verdictsOf(doc: Record<string, unknown>): Record<string, unknown>[] {
  return doc.verdicts as Record<string, unknown>[];
}

function requireVerdict(doc: Record<string, unknown>, status: string): Record<string, unknown> {
  const found = verdictsOf(doc).find((verdict) => verdict.status === status);
  if (found === undefined) {
    throw new Error(`fixture should contain a "${status}" verdict`);
  }
  return found;
}

describe("report JSON schema", () => {
  it("accepts the rendered report", () => {
    const valid = validate(reportDocument());
    expect(validate.errors ?? []).toEqual([]);
    expect(valid).toBe(true);
  });

  it("rejects a not_applicable verdict with no reason", () => {
    const doc = reportDocument();
    delete requireVerdict(doc, "not_applicable").reason;
    expect(validate(doc)).toBe(false);
  });

  it("rejects a pass verdict with no evidence", () => {
    const doc = reportDocument();
    requireVerdict(doc, "pass").evidence = [];
    expect(validate(doc)).toBe(false);
  });

  it("rejects a checkId that embeds the CCM control number", () => {
    const doc = reportDocument();
    requireVerdict(doc, "fail").checkId = "ivs-03/no-open-admin-ports";
    expect(validate(doc)).toBe(false);
  });

  it("rejects an out-of-scope CCM domain", () => {
    const doc = reportDocument();
    requireVerdict(doc, "fail").ccmId = "TVM-01";
    expect(validate(doc)).toBe(false);
  });

  it("rejects unknown top-level properties", () => {
    const doc = reportDocument();
    doc.somethingElse = true;
    expect(validate(doc)).toBe(false);
  });
});
