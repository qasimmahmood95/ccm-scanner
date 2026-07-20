import { describe, expect, it } from "vitest";
import type { Resource, ResourceModel, Status } from "../../src/index.js";
import { model, resource, run, statusOf, statusesOf } from "../support/checks.js";

/**
 * Boundary tests for the LOG and IVS checks.
 *
 * The fixture lane proves these work end to end. What it cannot reach is the
 * cases where a plausible-looking implementation is wrong: a port *range* that
 * spans a sensitive port without equalling it, ICMP reusing the port fields for
 * type and code, a control that checks half of what it claims and reports a
 * Pass, and every unknown-until-apply path.
 */

function trail(values: Record<string, unknown>, unknown: readonly string[] = []): Resource {
  return resource("aws_cloudtrail.main", "aws_cloudtrail", values, unknown);
}

const COMPLIANT_TRAIL = {
  is_multi_region_trail: true,
  include_global_service_events: true,
  enable_log_file_validation: true,
  s3_bucket_name: "logs",
};

function bucket(name = "logs"): Resource {
  return resource(`aws_s3_bucket.${name}`, "aws_s3_bucket", { bucket: name });
}

function fullBlock(name = "logs"): Resource {
  return resource(
    `aws_s3_bucket_public_access_block.${name}`,
    "aws_s3_bucket_public_access_block",
    {
      bucket: name,
      block_public_acls: true,
      block_public_policy: true,
      ignore_public_acls: true,
      restrict_public_buckets: true,
    },
  );
}

function sse(name = "logs"): Resource {
  return resource(
    `aws_s3_bucket_server_side_encryption_configuration.${name}`,
    "aws_s3_bucket_server_side_encryption_configuration",
    {
      bucket: name,
      rule: [{ apply_server_side_encryption_by_default: [{ sse_algorithm: "aws:kms" }] }],
    },
  );
}

describe("log/cloudtrail-multi-region", () => {
  const cases: readonly [string, Record<string, unknown>, Status][] = [
    ["a multi-region trail with global events", COMPLIANT_TRAIL, "pass"],
    ["a single-region trail", { ...COMPLIANT_TRAIL, is_multi_region_trail: false }, "fail"],
    // A trail that skips global service events records no IAM or STS activity
    // at all, which is precisely the activity an auditor asks about.
    [
      "a trail excluding global service events",
      { ...COMPLIANT_TRAIL, include_global_service_events: false },
      "fail",
    ],
    // Terraform defaults both to false, so absent is a real "not enabled".
    ["a trail declaring neither flag", { s3_bucket_name: "logs" }, "fail"],
  ];

  for (const [name, values, expected] of cases) {
    it(`is ${expected} for ${name}`, () => {
      expect(statusOf("log/cloudtrail-multi-region", model(trail(values)))).toBe(expected);
    });
  }

  // A trail is account-scoped and usually lives in a separate audit module, so
  // its absence here is not evidence the account has none.
  it("is not_applicable when no trail is declared", () => {
    const finding = run("log/cloudtrail-multi-region", model(bucket()))[0];
    expect(finding?.status).toBe("not_applicable");
    expect(finding?.reason).toContain("account-scoped");
  });

  it("is not_applicable when the flag is not known until apply", () => {
    const input = model(trail(COMPLIANT_TRAIL, ["is_multi_region_trail"]));
    expect(statusOf("log/cloudtrail-multi-region", input)).toBe("not_applicable");
  });
});

describe("log/cloudtrail-log-validation", () => {
  it("passes a validating trail whose log bucket is encrypted and blocked", () => {
    const input = model(trail(COMPLIANT_TRAIL), bucket(), sse(), fullBlock());
    expect(statusOf("log/cloudtrail-log-validation", input)).toBe("pass");
  });

  it("fails when log-file validation is off, whatever the bucket does", () => {
    const input = model(
      trail({ ...COMPLIANT_TRAIL, enable_log_file_validation: false }),
      bucket(),
      sse(),
      fullBlock(),
    );
    expect(statusOf("log/cloudtrail-log-validation", input)).toBe("fail");
  });

  // A tamper-evident log in a world-readable bucket is not a protected log.
  it("fails a validating trail whose log bucket has no public-access block", () => {
    const input = model(trail(COMPLIANT_TRAIL), bucket(), sse());
    expect(statusOf("log/cloudtrail-log-validation", input)).toBe("fail");
  });

  it("fails a validating trail whose log bucket is unencrypted", () => {
    const input = model(trail(COMPLIANT_TRAIL), bucket(), fullBlock());
    expect(statusOf("log/cloudtrail-log-validation", input)).toBe("fail");
  });

  // Half-checked is not checked: passing here would claim the logs are
  // protected when the bucket holding them was never examined.
  it("is not_applicable when the log bucket is not declared in this input", () => {
    const finding = run("log/cloudtrail-log-validation", model(trail(COMPLIANT_TRAIL)))[0];
    expect(finding?.status).toBe("not_applicable");
    expect(finding?.reason).toContain("does not declare");
  });

  it("is not_applicable when a correlator is not known until apply", () => {
    const unknownBlock = resource(
      "aws_s3_bucket_public_access_block.logs",
      "aws_s3_bucket_public_access_block",
      { bucket: "logs" },
      ["block_public_acls"],
    );
    const input = model(trail(COMPLIANT_TRAIL), bucket(), sse(), unknownBlock);
    expect(statusOf("log/cloudtrail-log-validation", input)).toBe("not_applicable");
  });

  // One flag off is a documented route to making the bucket public.
  it("fails when the public-access block enables only three of four flags", () => {
    const partial = resource(
      "aws_s3_bucket_public_access_block.logs",
      "aws_s3_bucket_public_access_block",
      {
        bucket: "logs",
        block_public_acls: true,
        block_public_policy: true,
        ignore_public_acls: true,
        restrict_public_buckets: false,
      },
    );
    const input = model(trail(COMPLIANT_TRAIL), bucket(), sse(), partial);
    expect(statusOf("log/cloudtrail-log-validation", input)).toBe("fail");
  });
});

describe("log/cloudtrail-accountability", () => {
  it("passes on CloudWatch Logs delivery alone", () => {
    const input = model(
      trail({ ...COMPLIANT_TRAIL, cloud_watch_logs_group_arn: "arn:aws:logs:::lg" }),
    );
    expect(statusOf("log/cloudtrail-accountability", input)).toBe("pass");
  });

  // Either signal satisfies the control, so the bucket path must work with no
  // CloudWatch group at all.
  it("passes on bucket access logging when there is no CloudWatch group", () => {
    const logging = resource("aws_s3_bucket_logging.logs", "aws_s3_bucket_logging", {
      bucket: "logs",
      target_bucket: "audit",
    });
    const input = model(trail(COMPLIANT_TRAIL), bucket(), logging);
    expect(statusOf("log/cloudtrail-accountability", input)).toBe("pass");
  });

  it("fails when the declared log bucket has neither signal", () => {
    expect(statusOf("log/cloudtrail-accountability", model(trail(COMPLIANT_TRAIL), bucket()))).toBe(
      "fail",
    );
  });

  it("is not_applicable when neither signal is declared in this input", () => {
    expect(statusOf("log/cloudtrail-accountability", model(trail(COMPLIANT_TRAIL)))).toBe(
      "not_applicable",
    );
  });
});

describe("log/vpc-flow-logs", () => {
  function vpc(id: unknown, unknown: readonly string[] = []): Resource {
    return resource("aws_vpc.main", "aws_vpc", { id, cidr_block: "10.0.0.0/16" }, unknown);
  }
  function flowLog(vpcId: unknown, unknown: readonly string[] = []): Resource {
    return resource("aws_flow_log.main", "aws_flow_log", { vpc_id: vpcId }, unknown);
  }

  it("passes a VPC with a flow log targeting it", () => {
    expect(statusOf("log/vpc-flow-logs", model(vpc("vpc-1"), flowLog("vpc-1")))).toBe("pass");
  });

  it("fails a VPC with no flow log", () => {
    expect(statusOf("log/vpc-flow-logs", model(vpc("vpc-1")))).toBe("fail");
  });

  // A flow log for a *different* VPC does not cover this one.
  it("fails a VPC whose only flow log targets another VPC", () => {
    expect(statusOf("log/vpc-flow-logs", model(vpc("vpc-1"), flowLog("vpc-2")))).toBe("fail");
  });

  // The whole reason this control is Partial: a create plan cannot resolve the
  // id, so claiming a Fail would be guessing.
  it("is not_applicable when the flow log's vpc_id is not known until apply", () => {
    const finding = run("log/vpc-flow-logs", model(vpc("vpc-1"), flowLog(null, ["vpc_id"])))[0];
    expect(finding?.status).toBe("not_applicable");
    expect(finding?.reason).toContain("not known until apply");
  });

  it("is not_applicable when the VPC's own id is not known until apply", () => {
    expect(statusOf("log/vpc-flow-logs", model(vpc(null, ["id"])))).toBe("not_applicable");
  });

  it("is not_applicable when no VPC is declared", () => {
    expect(statusOf("log/vpc-flow-logs", model(bucket()))).toBe("not_applicable");
  });
});

describe("ivs/no-open-admin-ports", () => {
  function sg(ingress: unknown, unknown: readonly string[] = []): ResourceModel {
    return model(resource("aws_security_group.web", "aws_security_group", { ingress }, unknown));
  }
  const open = (extra: Record<string, unknown>): Record<string, unknown> => ({
    protocol: "tcp",
    cidr_blocks: ["0.0.0.0/0"],
    ...extra,
  });

  it("fails SSH open to the world", () => {
    expect(statusOf("ivs/no-open-admin-ports", sg([open({ from_port: 22, to_port: 22 })]))).toBe(
      "fail",
    );
  });

  // The bug a naive `from_port === port` check would ship: the range spans 22
  // without ever equalling it.
  it("fails a port range that spans a sensitive port without equalling it", () => {
    expect(statusOf("ivs/no-open-admin-ports", sg([open({ from_port: 20, to_port: 25 })]))).toBe(
      "fail",
    );
  });

  it("fails a rule opening every port to the world", () => {
    expect(statusOf("ivs/no-open-admin-ports", sg([open({ from_port: 0, to_port: 65535 })]))).toBe(
      "fail",
    );
  });

  // protocol "-1" means all protocols and all ports whatever the port fields say.
  it("fails an all-protocols rule regardless of its port fields", () => {
    expect(
      statusOf("ivs/no-open-admin-ports", sg([open({ from_port: 0, to_port: 0, protocol: "-1" })])),
    ).toBe("fail");
  });

  it("fails IPv6 exposure via ::/0", () => {
    expect(
      statusOf(
        "ivs/no-open-admin-ports",
        sg([{ from_port: 22, to_port: 22, protocol: "tcp", ipv6_cidr_blocks: ["::/0"] }]),
      ),
    ).toBe("fail");
  });

  it("passes HTTPS open to the world", () => {
    expect(statusOf("ivs/no-open-admin-ports", sg([open({ from_port: 443, to_port: 443 })]))).toBe(
      "pass",
    );
  });

  // The port is sensitive but the source is not the world.
  it("passes SSH restricted to a private range", () => {
    expect(
      statusOf(
        "ivs/no-open-admin-ports",
        sg([{ from_port: 22, to_port: 22, protocol: "tcp", cidr_blocks: ["10.0.0.0/8"] }]),
      ),
    ).toBe("pass");
  });

  // ICMP reuses from_port/to_port as type and code, so treating them as TCP
  // ports would compare unrelated numbers and invent a failure.
  it("passes world-open ICMP, whose port fields are type and code", () => {
    expect(
      statusOf(
        "ivs/no-open-admin-ports",
        sg([{ from_port: 8, to_port: 0, protocol: "icmp", cidr_blocks: ["0.0.0.0/0"] }]),
      ),
    ).toBe("pass");
  });

  it("is not_applicable when the ingress block is not known until apply", () => {
    const finding = run("ivs/no-open-admin-ports", sg(null, ["ingress"]))[0];
    expect(finding?.status).toBe("not_applicable");
    expect(finding?.reason).toContain("not known until apply");
  });

  it("is not_applicable when no ingress rules are declared at all", () => {
    expect(statusOf("ivs/no-open-admin-ports", model(bucket()))).toBe("not_applicable");
  });

  // An egress rule to the world is ordinary and must not be read as ingress.
  it("ignores an egress security-group rule", () => {
    const rule = resource("aws_security_group_rule.out", "aws_security_group_rule", {
      type: "egress",
      from_port: 22,
      to_port: 22,
      protocol: "tcp",
      cidr_blocks: ["0.0.0.0/0"],
    });
    expect(statusOf("ivs/no-open-admin-ports", model(rule))).toBe("not_applicable");
  });

  it("fails a standalone ingress rule", () => {
    const rule = resource("aws_security_group_rule.in", "aws_security_group_rule", {
      type: "ingress",
      from_port: 3389,
      to_port: 3389,
      protocol: "tcp",
      cidr_blocks: ["0.0.0.0/0"],
    });
    expect(statusOf("ivs/no-open-admin-ports", model(rule))).toBe("fail");
  });

  // The newer resource type names the same concepts differently.
  it("fails a vpc-security-group ingress rule using cidr_ipv4 and ip_protocol", () => {
    const rule = resource(
      "aws_vpc_security_group_ingress_rule.in",
      "aws_vpc_security_group_ingress_rule",
      { from_port: 5432, to_port: 5432, ip_protocol: "tcp", cidr_ipv4: "0.0.0.0/0" },
    );
    expect(statusOf("ivs/no-open-admin-ports", model(rule))).toBe("fail");
  });

  it("fails an open admin port on the default security group", () => {
    const group = resource("aws_default_security_group.d", "aws_default_security_group", {
      ingress: [{ from_port: 22, to_port: 22, protocol: "tcp", cidr_blocks: ["0.0.0.0/0"] }],
    });
    expect(statusOf("ivs/no-open-admin-ports", model(group))).toBe("fail");
  });
});

describe("ivs/s3-public-access-block", () => {
  it("passes a bucket with all four flags enabled", () => {
    expect(statusOf("ivs/s3-public-access-block", model(bucket(), fullBlock()))).toBe("pass");
  });

  it("fails a bucket with no public-access block", () => {
    expect(statusOf("ivs/s3-public-access-block", model(bucket()))).toBe("fail");
  });

  it("fails an RDS instance with a public endpoint", () => {
    const db = resource("aws_db_instance.main", "aws_db_instance", { publicly_accessible: true });
    expect(statusOf("ivs/s3-public-access-block", model(db))).toBe("fail");
  });

  // Terraform defaults this to false, so absent really is "not public".
  it("passes an RDS instance that does not declare publicly_accessible", () => {
    const db = resource("aws_db_instance.main", "aws_db_instance", { engine: "postgres" });
    expect(statusOf("ivs/s3-public-access-block", model(db))).toBe("pass");
  });

  it("is not_applicable when publicly_accessible is not known until apply", () => {
    const db = resource("aws_db_instance.main", "aws_db_instance", { publicly_accessible: null }, [
      "publicly_accessible",
    ]);
    expect(statusOf("ivs/s3-public-access-block", model(db))).toBe("not_applicable");
  });

  it("is not_applicable when neither resource type is declared", () => {
    expect(statusOf("ivs/s3-public-access-block", model(trail(COMPLIANT_TRAIL)))).toBe(
      "not_applicable",
    );
  });
});

describe("ivs/default-sg-locked-down", () => {
  function defaultSg(values: Record<string, unknown>, unknown: readonly string[] = []): Resource {
    return resource("aws_default_security_group.d", "aws_default_security_group", values, unknown);
  }

  it("passes a default group with no rules", () => {
    expect(
      statusOf("ivs/default-sg-locked-down", model(defaultSg({ ingress: [], egress: [] }))),
    ).toBe("pass");
  });

  it("fails a default group carrying an ingress rule", () => {
    const input = model(
      defaultSg({
        ingress: [{ from_port: 0, to_port: 0, protocol: "-1", self: true }],
        egress: [],
      }),
    );
    expect(statusOf("ivs/default-sg-locked-down", input)).toBe("fail");
  });

  // Egress counts too — the control is that the group carries no rules at all.
  it("fails a default group carrying only an egress rule", () => {
    const input = model(
      defaultSg({ ingress: [], egress: [{ from_port: 0, to_port: 0, protocol: "-1" }] }),
    );
    expect(statusOf("ivs/default-sg-locked-down", input)).toBe("fail");
  });

  it("is not_applicable when the rules are not known until apply", () => {
    expect(
      statusOf("ivs/default-sg-locked-down", model(defaultSg({ ingress: null }, ["ingress"]))),
    ).toBe("not_applicable");
  });

  // Leaving the default group unmanaged is not evidence either way: it still
  // exists in the account with whatever rules it already had.
  it("is not_applicable when the default group is not managed here", () => {
    const finding = run("ivs/default-sg-locked-down", model(bucket()))[0];
    expect(finding?.status).toBe("not_applicable");
    expect(finding?.reason).toContain("unmanaged");
  });
});

describe("every LOG and IVS check", () => {
  it("gives a reason with every not-applicable verdict", () => {
    const empty = model();
    for (const checkId of [
      "log/cloudtrail-multi-region",
      "log/cloudtrail-log-validation",
      "log/cloudtrail-accountability",
      "log/vpc-flow-logs",
      "log/na-operational",
      "log/na-host-runtime",
      "ivs/no-open-admin-ports",
      "ivs/s3-public-access-block",
      "ivs/default-sg-locked-down",
      "ivs/na-host-config",
      "ivs/na-documentation",
    ]) {
      expect(statusesOf(checkId, empty), checkId).toEqual(["not_applicable"]);
      for (const finding of run(checkId, empty)) {
        expect(finding.reason ?? "", checkId).not.toBe("");
      }
    }
  });
});
