import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { allChecks } from "../../src/controls/index.js";
import { createRegistry, evaluate, ingestTerraformPlan, type Verdict } from "../../src/index.js";
import { rowsWithCoverage } from "../support/mapping.js";

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

/** Identify by (control, check) pair — de-duplicating by control hides regressions. */
function pairsWithStatus(verdicts: readonly Verdict[], status: Verdict["status"]): string[] {
  return [
    ...new Set(
      verdicts
        .filter((verdict) => verdict.status === status)
        .map((verdict) => `${verdict.ccmId} ${verdict.checkId}`),
    ),
  ].sort();
}

describe("the compliant fixture", () => {
  it("produces no failures at all", () => {
    expect(pairsWithStatus(compliant, "fail")).toEqual([]);
  });

  it("passes each control that is evidenceable from it", () => {
    expect(pairsWithStatus(compliant, "pass")).toEqual([
      "CEK-03 cek/encryption-at-rest",
      "CEK-03 cek/tls-enforced",
      "CEK-04 cek/approved-algorithms",
      "CEK-12 cek/kms-key-rotation",
      "IAM-02 iam/account-password-policy",
      "IAM-05 iam/no-wildcard-allow",
      "IAM-14 iam/mfa-enforcement-present",
      "IAM-15 iam/password-lifecycle",
      "IAM-16 iam/no-wildcard-trust",
    ]);
  });

  it("gives every not-applicable verdict a reason", () => {
    for (const verdict of compliant.filter((v) => v.status === "not_applicable")) {
      expect(verdict.reason ?? "", verdict.checkId).not.toBe("");
    }
  });
});

describe("the non-compliant fixture", () => {
  it("fails exactly the control/check pairs it is built to violate", () => {
    expect(pairsWithStatus(nonCompliant, "fail")).toEqual([
      "CEK-03 cek/encryption-at-rest",
      "CEK-03 cek/tls-enforced",
      "CEK-04 cek/approved-algorithms",
      "CEK-12 cek/kms-key-rotation",
      "IAM-02 iam/account-password-policy",
      "IAM-05 iam/no-wildcard-allow",
      "IAM-15 iam/password-lifecycle",
      "IAM-16 iam/no-wildcard-trust",
    ]);
  });

  it("flags the wildcard policy against IAM-05, not some neighbouring control", () => {
    const verdict = nonCompliant.find(
      (candidate) => candidate.status === "fail" && candidate.checkId === "iam/no-wildcard-allow",
    );
    expect(verdict?.ccmId).toBe("IAM-05");
    expect(verdict?.ccmTitle).toBe("Least Privilege");
    expect(verdict?.evidence[0]?.resourceAddress).toBe("aws_iam_policy.admin");
  });

  it("flags the world-assumable role against IAM-16", () => {
    const verdict = nonCompliant.find(
      (candidate) => candidate.status === "fail" && candidate.checkId === "iam/no-wildcard-trust",
    );
    expect(verdict?.ccmId).toBe("IAM-16");
    expect(verdict?.evidence[0]?.resourceAddress).toBe("aws_iam_role.public");
  });

  it("flags the unrotated key against CEK-12", () => {
    const verdict = nonCompliant.find(
      (candidate) => candidate.status === "fail" && candidate.checkId === "cek/kms-key-rotation",
    );
    expect(verdict?.ccmId).toBe("CEK-12");
    expect(verdict?.evidence[0]?.resourceAddress).toBe("aws_kms_key.unrotated");
    expect(verdict?.evidence[0]?.observed).toBe(false);
  });

  it("flags the weak TLS policy against CEK-04", () => {
    const failures = nonCompliant.filter(
      (candidate) => candidate.status === "fail" && candidate.checkId === "cek/approved-algorithms",
    );
    const addresses = failures.flatMap((v) => v.evidence.map((item) => item.resourceAddress));
    expect(addresses).toContain("aws_lb_listener.legacy");
  });

  it("flags the unencrypted database against CEK-03", () => {
    const failures = nonCompliant.filter(
      (candidate) => candidate.status === "fail" && candidate.checkId === "cek/encryption-at-rest",
    );
    const addresses = failures.flatMap((v) => v.evidence.map((item) => item.resourceAddress));
    expect(addresses).toContain("module.storage.aws_db_instance.main");
  });
});

/**
 * ADR-0003 requires every Yes/Partial control to have both a compliant and a
 * non-compliant fixture. Without this the suite cannot detect a check that has
 * been stubbed out — which is exactly how a whole check can silently stop
 * working while the report keeps claiming coverage.
 */
describe("fixture coverage (ADR-0003)", () => {
  it("gives every Yes control a failing case", () => {
    for (const row of rowsWithCoverage(["Yes"])) {
      expect(
        nonCompliant.some((v) => v.checkId === row.checkId && v.status === "fail"),
        `${row.ccmId} (${row.checkId ?? "?"}) has no failing case in the non-compliant fixture`,
      ).toBe(true);
    }
  });

  it("gives every Yes and Partial control a passing case", () => {
    for (const row of rowsWithCoverage(["Yes", "Partial"])) {
      expect(
        compliant.some((v) => v.checkId === row.checkId && v.status === "pass"),
        `${row.ccmId} (${row.checkId ?? "?"}) has no passing case in the compliant fixture`,
      ).toBe(true);
    }
  });

  it("reports every NA control as not-applicable in both fixtures", () => {
    for (const row of rowsWithCoverage(["NA"])) {
      for (const [name, verdicts] of [
        ["compliant", compliant],
        ["non-compliant", nonCompliant],
      ] as const) {
        expect(
          verdicts.some((v) => v.checkId === row.checkId && v.status === "not_applicable"),
          `${row.ccmId} should be not-applicable in the ${name} fixture`,
        ).toBe(true);
      }
    }
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
    expect(
      nonCompliant.some(
        (candidate) =>
          candidate.status === "fail" &&
          candidate.evidence.some((item) => item.resourceAddress === "aws_ebs_volume.data"),
      ),
    ).toBe(false);
  });
});
