import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { allChecks } from "../../src/controls/index.js";
import { createRegistry, evaluate, ingestTerraformPlan, type Verdict } from "../../src/index.js";

/**
 * The end-to-end contract: ingest a fixture, run every registered check, and
 * confirm the compliant input is clean while the non-compliant one is flagged
 * with the *correct CCM control ids*. A check that fires on the wrong control
 * is worse than one that does not fire at all.
 */
function scan(fixture: string): readonly Verdict[] {
  const raw = readFileSync(new URL(`../../fixtures/${fixture}`, import.meta.url), "utf8");
  const { model } = ingestTerraformPlan(raw, fixture);
  return evaluate(createRegistry(allChecks).select(), model);
}

const compliant = scan("compliant/terraform-plan.json");
const nonCompliant = scan("non-compliant/terraform-plan.json");

function controlsWithStatus(verdicts: readonly Verdict[], status: Verdict["status"]): string[] {
  return [
    ...new Set(verdicts.filter((verdict) => verdict.status === status).map((v) => v.ccmId)),
  ].sort();
}

describe("the compliant fixture", () => {
  it("produces no failures at all", () => {
    const failures = compliant.filter((verdict) => verdict.status === "fail");
    expect(
      failures.map((verdict) => `${verdict.ccmId} ${verdict.checkId}`),
      "compliant fixture must be clean",
    ).toEqual([]);
  });

  it("passes each control that is evidenceable from it", () => {
    expect(controlsWithStatus(compliant, "pass")).toEqual([
      "CEK-03",
      "CEK-04",
      "CEK-12",
      "IAM-02",
      "IAM-05",
      "IAM-14",
      "IAM-15",
      "IAM-16",
    ]);
  });

  it("reports the process and governance controls as not applicable, with reasons", () => {
    const notApplicable = compliant.filter((verdict) => verdict.status === "not_applicable");
    expect(controlsWithStatus(compliant, "not_applicable")).toEqual([
      "CEK-01",
      "CEK-14",
      "IAM-03",
      "IAM-08",
    ]);
    for (const verdict of notApplicable) {
      expect(verdict.reason ?? "", verdict.ccmId).not.toBe("");
    }
  });
});

describe("the non-compliant fixture", () => {
  it("fails exactly the controls it is built to violate", () => {
    expect(controlsWithStatus(nonCompliant, "fail")).toEqual(["CEK-03", "CEK-12", "IAM-05"]);
  });

  it("flags the wildcard policy against IAM-05, not some neighbouring control", () => {
    const verdict = nonCompliant.find(
      (candidate) => candidate.status === "fail" && candidate.checkId === "iam/no-wildcard-allow",
    );
    expect(verdict?.ccmId).toBe("IAM-05");
    expect(verdict?.ccmTitle).toBe("Least Privilege");
    expect(verdict?.evidence[0]?.resourceAddress).toBe("aws_iam_policy.admin");
  });

  it("flags the unrotated key against CEK-12", () => {
    const verdict = nonCompliant.find(
      (candidate) => candidate.status === "fail" && candidate.checkId === "cek/kms-key-rotation",
    );
    expect(verdict?.ccmId).toBe("CEK-12");
    expect(verdict?.evidence[0]?.resourceAddress).toBe("aws_kms_key.unrotated");
    expect(verdict?.evidence[0]?.observed).toBe(false);
  });

  it("flags the unencrypted database against CEK-03", () => {
    const failures = nonCompliant.filter(
      (candidate) => candidate.status === "fail" && candidate.checkId === "cek/encryption-at-rest",
    );
    const addresses = failures.flatMap((verdict) =>
      verdict.evidence.map((item) => item.resourceAddress),
    );
    expect(addresses).toContain("module.storage.aws_db_instance.main");
  });
});

// The whole point of carrying unknownAttributes through ingestion.
describe("values not known until apply", () => {
  it("reports not-applicable rather than guessing", () => {
    const verdict = nonCompliant.find(
      (candidate) =>
        candidate.checkId === "cek/encryption-at-rest" &&
        candidate.status === "not_applicable" &&
        (candidate.reason ?? "").includes("aws_ebs_volume.data"),
    );

    expect(verdict, "the EBS volume's encrypted flag is unknown until apply").toBeDefined();
    expect(verdict?.reason).toContain("not known until apply");
    // It must not have been read as "absent" and failed.
    expect(
      nonCompliant.some(
        (candidate) =>
          candidate.status === "fail" &&
          candidate.evidence.some((item) => item.resourceAddress === "aws_ebs_volume.data"),
      ),
    ).toBe(false);
  });
});
