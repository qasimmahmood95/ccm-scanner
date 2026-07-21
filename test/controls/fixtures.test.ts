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
      "IVS-03 ivs/no-open-admin-ports",
      "IVS-03 ivs/s3-public-access-block",
      "IVS-06 ivs/default-sg-locked-down",
      "LOG-02 log/cloudtrail-log-validation",
      "LOG-03 log/vpc-flow-logs",
      "LOG-04 log/cloudtrail-accountability",
      "LOG-07 log/cloudtrail-multi-region",
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
      "IVS-03 ivs/no-open-admin-ports",
      "IVS-03 ivs/s3-public-access-block",
      "IVS-06 ivs/default-sg-locked-down",
      "LOG-02 log/cloudtrail-log-validation",
      "LOG-03 log/vpc-flow-logs",
      "LOG-04 log/cloudtrail-accountability",
      "LOG-07 log/cloudtrail-multi-region",
    ]);
  });

  it("flags the world-open SSH rule against IVS-03", () => {
    const verdict = nonCompliant.find(
      (candidate) => candidate.status === "fail" && candidate.checkId === "ivs/no-open-admin-ports",
    );
    expect(verdict?.ccmId).toBe("IVS-03");
    expect(verdict?.ccmTitle).toBe("Network Security");
    expect(verdict?.evidence[0]?.resourceAddress).toBe("aws_security_group.admin");
  });

  it("flags the single-region trail against LOG-07, not a neighbouring LOG control", () => {
    const verdict = nonCompliant.find(
      (candidate) =>
        candidate.status === "fail" && candidate.checkId === "log/cloudtrail-multi-region",
    );
    expect(verdict?.ccmId).toBe("LOG-07");
    expect(verdict?.ccmTitle).toBe("Logging Scope");
    expect(verdict?.evidence[0]?.resourceAddress).toBe("aws_cloudtrail.regional");
  });

  it("flags the VPC without a flow log against LOG-03", () => {
    const verdict = nonCompliant.find(
      (candidate) => candidate.status === "fail" && candidate.checkId === "log/vpc-flow-logs",
    );
    expect(verdict?.ccmId).toBe("LOG-03");
    expect(verdict?.evidence[0]?.resourceAddress).toBe("aws_vpc.main");
  });

  it("flags the rule-bearing default security group against IVS-06", () => {
    const verdict = nonCompliant.find(
      (candidate) =>
        candidate.status === "fail" && candidate.checkId === "ivs/default-sg-locked-down",
    );
    expect(verdict?.ccmId).toBe("IVS-06");
    expect(verdict?.evidence[0]?.resourceAddress).toBe("aws_default_security_group.default");
  });

  // The default SG's rule is self-referential, not world-open, so it must not
  // also be reported as an exposed port — each fixture defect trips one control.
  it("does not report the default security group as an open admin port", () => {
    const addresses = nonCompliant
      .filter((v) => v.status === "fail" && v.checkId === "ivs/no-open-admin-ports")
      .flatMap((v) => v.evidence.map((item) => item.resourceAddress));
    expect(addresses).not.toContain("aws_default_security_group.default");
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
 * Deferred M4 review finding F-5. Four verdict paths were exercised only by the
 * hand-written boundary tests in `boundaries-log-ivs.test.ts`, never by the
 * fixture-derived goldens. The fixtures were extended so those goldens are a
 * fuller specimen and the four mutants the boundary tests pin are also killed by
 * the end-to-end lane. These assertions name each path; the goldens hold the
 * exact evidence and reasons. Both lanes carry the same resources, so the
 * additions did not change which control/check pairs pass or fail above.
 */
describe("F-5 verdict paths, exercised end to end", () => {
  // Paths 1 and 3. A trail with no CloudWatch group whose log bucket carries
  // access logging reaches LOG-04's `covered` branch (path 1). Two
  // aws_s3_bucket_logging resources target that one bucket, so correlateBy must
  // accumulate and the branch must cite *both* satellites, not only the last
  // one seen (path 3).
  it("passes LOG-04 via bucket access logging, citing every logging satellite", () => {
    const verdict = compliant.find(
      (v) =>
        v.checkId === "log/cloudtrail-accountability" &&
        v.evidence.some((item) => item.resourceAddress === "aws_cloudtrail.audit"),
    );
    expect(verdict?.status).toBe("pass");
    const cited = verdict?.evidence.map((item) => item.resourceAddress) ?? [];
    expect(cited).toContain("aws_s3_bucket_logging.audit");
    expect(cited).toContain("aws_s3_bucket_logging.audit_extra");
  });

  // Path 2. The audit trail's log bucket is declared in another module, so its
  // LOG-02 verdict rests on the satellites alone: there is no aws_s3_bucket to
  // cite, and nothing "holds the logs".
  it("passes LOG-02 on the satellites alone when the log bucket is declared elsewhere", () => {
    const verdict = compliant.find(
      (v) =>
        v.checkId === "log/cloudtrail-log-validation" &&
        v.evidence.some((item) => item.resourceAddress === "aws_cloudtrail.audit"),
    );
    expect(verdict?.status).toBe("pass");
    const cited = verdict?.evidence.map((item) => item.resourceAddress) ?? [];
    expect(cited).toContain("aws_s3_bucket_server_side_encryption_configuration.audit");
    expect(cited).toContain("aws_s3_bucket_public_access_block.audit");
    expect(verdict?.evidence.some((item) => String(item.observed).includes("holds the logs"))).toBe(
      false,
    );
  });

  // Path 4. More VPCs than a declared default security group covers, where one
  // group omits its vpc_id, so the pairing cannot be resolved and the check
  // counts rather than names. This branch needs an unresolvable id; a snapshot
  // has no unknown-until-apply, so the fixture reaches it with a vpc_id-less
  // default group instead — a shape both lanes share.
  it("reports IVS-06's counting branch when a default group omits its vpc_id", () => {
    const verdict = nonCompliant.find(
      (v) => v.checkId === "ivs/default-sg-locked-down" && v.status === "not_applicable",
    );
    expect(verdict?.reason).toContain("3 VPC(s) but only 2 of them are covered");
    expect(verdict?.reason).toContain("declares no vpc_id");
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
