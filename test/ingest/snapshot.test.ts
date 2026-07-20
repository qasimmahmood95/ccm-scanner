import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { allChecks } from "../../src/controls/index.js";
import {
  createRegistry,
  detectFormat,
  evaluate,
  ingest,
  ingestSnapshot,
  IngestError,
  type Verdict,
} from "../../src/index.js";

/**
 * The snapshot lane, and the property M6 exists to deliver: the same checks
 * over observed cloud state produce the same verdicts as over the equivalent
 * Terraform.
 *
 * The fixtures are committed, hand-maintained documents. Deriving one from the
 * other at test time would make the comparison tautological — it would prove
 * only that a round-trip round-trips.
 */
function fixture(name: string): string {
  return readFileSync(new URL(`../../fixtures/${name}`, import.meta.url), "utf8");
}

function scan(name: string): readonly Verdict[] {
  const { model } = ingest(fixture(name), name);
  return evaluate(createRegistry(allChecks).select(), model);
}

/** Verdicts as comparable text, with the input's own address kept. */
function stream(verdicts: readonly Verdict[]): string[] {
  return verdicts.map(
    (verdict) =>
      `${verdict.ccmId} ${verdict.checkId} ${verdict.status} ` +
      verdict.evidence.map((item) => item.resourceAddress).join(","),
  );
}

describe("format detection", () => {
  it("recognises a snapshot by its version marker", () => {
    expect(detectFormat(fixture("snapshot/compliant.json"))).toBe("snapshot");
  });

  it("recognises Terraform output", () => {
    expect(detectFormat(fixture("compliant/terraform-plan.json"))).toBe("terraform");
  });

  // Neither shape is not a reason to guess: an empty model would scan clean.
  it("declines a document matching neither format", () => {
    expect(detectFormat('{"hello":"world"}')).toBeUndefined();
    expect(() => ingest('{"hello":"world"}', "x")).toThrow(/neither supported format/);
  });

  it("honours an explicit override", () => {
    expect(() => ingest(fixture("compliant/terraform-plan.json"), "x", "snapshot")).toThrow(
      IngestError,
    );
  });
});

describe("the snapshot adapter", () => {
  it("reads a snapshot into the same model shape", () => {
    const { model, warnings } = ingestSnapshot(fixture("snapshot/compliant.json"), "s");
    expect(model.resources.length).toBeGreaterThan(10);
    expect(warnings).toEqual([]);
    expect(model.resources.map((resource) => resource.address)).toEqual(
      [...model.resources.map((resource) => resource.address)].sort(),
    );
  });

  // Observed state, so nothing is pending. This is what lets a snapshot decide
  // a control the equivalent plan had to decline.
  it("marks nothing unknown-until-apply", () => {
    const { model } = ingestSnapshot(fixture("snapshot/non-compliant.json"), "s");
    expect(model.resources.every((resource) => resource.unknownAttributes.length === 0)).toBe(true);
  });

  it("derives the provider from the resource type", () => {
    const { model } = ingestSnapshot(fixture("snapshot/compliant.json"), "s");
    expect(new Set(model.resources.map((resource) => resource.provider))).toEqual(new Set(["aws"]));
  });

  it("carries sensitive markings through, so redaction still applies", () => {
    const { model } = ingestSnapshot(fixture("snapshot/non-compliant.json"), "s");
    const db = model.resources.find(
      (resource) => resource.address === "module.storage.aws_db_instance.main",
    );
    expect(db?.sensitiveAttributes).toContain("password");
  });

  const rejects: readonly [string, string, RegExp][] = [
    ["a non-JSON document", "not json", /not valid JSON/],
    ["a JSON array", "[]", /JSON object/],
    ["a missing version marker", '{"resources":[]}', /version marker/],
    ["an unsupported version", '{"ccmScannerSnapshot":"99","resources":[]}', /not supported/],
    [
      "a non-array resources field",
      '{"ccmScannerSnapshot":"1","resources":{}}',
      /must be an array/,
    ],
  ];
  for (const [name, raw, message] of rejects) {
    it(`rejects ${name}`, () => {
      expect(() => ingestSnapshot(raw, "s")).toThrow(message);
    });
  }

  // Skipping an entry silently would shrink the scan without shrinking the
  // report's apparent coverage.
  it("warns about every entry it skips, naming it", () => {
    const raw = JSON.stringify({
      ccmScannerSnapshot: "1",
      resources: [
        "not-an-object",
        { type: "aws_s3_bucket" },
        { address: "aws_s3_bucket.a" },
        { address: "aws_s3_bucket.b", type: "aws_s3_bucket", attributes: { bucket: "b" } },
        { address: "aws_s3_bucket.b", type: "aws_s3_bucket", attributes: { bucket: "b" } },
      ],
    });
    const { model, warnings } = ingestSnapshot(raw, "s");
    expect(model.resources.map((resource) => resource.address)).toEqual(["aws_s3_bucket.b"]);
    expect(warnings).toHaveLength(4);
    expect(warnings.join(" ")).toContain("duplicate address");
  });

  it("warns rather than scanning clean when a snapshot is empty", () => {
    const { warnings } = ingestSnapshot('{"ccmScannerSnapshot":"1","resources":[]}', "s");
    expect(warnings).toContain("no resources found in the snapshot");
  });
});

/**
 * M6's exit criterion, as a test rather than a claim.
 */
describe("the two lanes agree", () => {
  it("produces identical verdicts for the compliant infrastructure", () => {
    expect(stream(scan("snapshot/compliant.json"))).toEqual(
      stream(scan("compliant/terraform-plan.json")),
    );
  });

  /**
   * One documented divergence, and it is the point rather than a defect.
   *
   * The plan cannot know `aws_ebs_volume.data.encrypted` until apply, so
   * CEK-03 declines it. The snapshot observed the volume unencrypted, so
   * CEK-03 fails it. A snapshot deciding what a plan could not is the lane
   * working, and the equality above holds everywhere it is not involved.
   */
  it("differs only where the snapshot knows what the plan could not", () => {
    // The plan's verdict carries the volume in its *reason* (it declined, so
    // it has no evidence); the snapshot's carries it in evidence. Matching on
    // either is what identifies the pair.
    const mentionsVolume = (verdict: Verdict): boolean =>
      (verdict.reason ?? "").includes("aws_ebs_volume.data") ||
      verdict.evidence.some((item) => item.resourceAddress === "aws_ebs_volume.data");

    const fromPlan = scan("non-compliant/terraform-plan.json");
    const fromSnapshot = scan("snapshot/non-compliant.json");

    expect(stream(fromSnapshot.filter((verdict) => !mentionsVolume(verdict)))).toEqual(
      stream(fromPlan.filter((verdict) => !mentionsVolume(verdict))),
    );

    const planVolume = fromPlan.find(mentionsVolume);
    expect(planVolume?.status).toBe("not_applicable");
    expect(planVolume?.reason).toContain("not known until apply");

    const snapshotVolume = fromSnapshot.find(mentionsVolume);
    expect(snapshotVolume?.status).toBe("fail");
    expect(snapshotVolume?.evidence[0]?.observed).toBe(false);

    // Exactly one control diverges, so the equality above is not vacuous.
    expect(fromPlan.filter(mentionsVolume)).toHaveLength(1);
    expect(fromSnapshot.filter(mentionsVolume)).toHaveLength(1);
  });

  it("flags the same controls in the non-compliant snapshot", () => {
    const failed = new Set(
      scan("snapshot/non-compliant.json")
        .filter((verdict) => verdict.status === "fail")
        .map((verdict) => verdict.ccmId),
    );
    for (const expected of ["IAM-05", "IAM-16", "CEK-03", "CEK-12", "LOG-07", "IVS-03", "IVS-06"]) {
      expect(failed, expected).toContain(expected);
    }
  });

  it("produces no failures for the compliant snapshot", () => {
    expect(scan("snapshot/compliant.json").filter((verdict) => verdict.status === "fail")).toEqual(
      [],
    );
  });
});
