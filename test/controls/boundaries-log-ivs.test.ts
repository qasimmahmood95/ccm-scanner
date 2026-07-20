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
  // ports would compare unrelated numbers and invent a failure. The type must
  // exceed a sensitive port for this to discriminate: an `icmp 8 -> 0` case
  // spans [0,8], which contains no sensitive port and so passes either way.
  it("passes world-open ICMPv6 whose type spans a sensitive port number", () => {
    expect(
      statusOf(
        "ivs/no-open-admin-ports",
        sg([{ from_port: 128, to_port: 0, protocol: "icmpv6", cidr_blocks: ["0.0.0.0/0"] }]),
      ),
    ).toBe("pass");
  });

  // Every port in the list, not just the three that happen to appear elsewhere.
  for (const port of [22, 3389, 3306, 5432, 1433, 27017, 6379]) {
    it(`fails world-open port ${String(port)}`, () => {
      expect(
        statusOf("ivs/no-open-admin-ports", sg([open({ from_port: port, to_port: port })])),
      ).toBe("fail");
    });
  }

  it("reads a port carried as a string", () => {
    expect(
      statusOf("ivs/no-open-admin-ports", sg([open({ from_port: "22", to_port: "22" })])),
    ).toBe("fail");
  });

  it("ignores surrounding whitespace in a CIDR", () => {
    expect(
      statusOf(
        "ivs/no-open-admin-ports",
        sg([{ from_port: 22, to_port: 22, protocol: "tcp", cidr_blocks: [" 0.0.0.0/0 "] }]),
      ),
    ).toBe("fail");
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

/**
 * Every case below is a verdict the M4 review gate found wrong, or found
 * correct but unpinned. Both are worth a test: the second class is how a fix
 * silently regresses.
 */
describe("regressions found by the M4 review gate", () => {
  const sgRule = (values: Record<string, unknown>, unknown: readonly string[] = []): Resource =>
    resource("aws_security_group_rule.r", "aws_security_group_rule", values, unknown);

  // MB-1. A flow log may legitimately target a subnet or ENI, leaving vpc_id
  // absent; reading that as "unreadable" let one compliant resource suppress
  // the Fail for every uncovered VPC in the input.
  it("fails an uncovered VPC despite a subnet-scoped flow log", () => {
    const input = model(
      resource("aws_vpc.main", "aws_vpc", { id: "vpc-a" }),
      resource("aws_flow_log.subnet", "aws_flow_log", { subnet_id: "subnet-b" }),
    );
    expect(statusOf("log/vpc-flow-logs", input)).toBe("fail");
  });

  it("fails every uncovered VPC when the only flow log is ENI-scoped", () => {
    const input = model(
      resource("aws_vpc.a", "aws_vpc", { id: "vpc-a" }),
      resource("aws_vpc.b", "aws_vpc", { id: "vpc-b" }),
      resource("aws_flow_log.eni", "aws_flow_log", { eni_id: "eni-1" }),
    );
    expect(statusesOf("log/vpc-flow-logs", input)).toEqual(["fail", "fail"]);
  });

  // MB-2. The newer rule shape guarded cidr_ipv6; this one did not guard its
  // equivalent, so a Pass was reported citing an empty CIDR list as evidence.
  it("is not_applicable when a standalone rule's ipv6_cidr_blocks is unknown", () => {
    const input = model(
      sgRule(
        {
          type: "ingress",
          from_port: 22,
          to_port: 22,
          protocol: "tcp",
          cidr_blocks: [],
          ipv6_cidr_blocks: null,
        },
        ["ipv6_cidr_blocks"],
      ),
    );
    expect(statusOf("ivs/no-open-admin-ports", input)).toBe("not_applicable");
  });

  // SF-1. Either signal satisfies LOG-04, so an unknown CloudWatch ARN — the
  // ordinary shape when it references a log group built in the same plan —
  // must not hide a bucket that demonstrably has access logging.
  it("passes on access logging even when the CloudWatch ARN is unknown", () => {
    const input = model(
      trail({ s3_bucket_name: "logs", cloud_watch_logs_group_arn: null }, [
        "cloud_watch_logs_group_arn",
      ]),
      bucket(),
      resource("aws_s3_bucket_logging.logs", "aws_s3_bucket_logging", { bucket: "logs" }),
    );
    expect(statusOf("log/cloudtrail-accountability", input)).toBe("pass");
  });

  it("declines rather than fails when the CloudWatch ARN is unknown and the bucket is not logged", () => {
    const input = model(
      trail({ s3_bucket_name: "logs", cloud_watch_logs_group_arn: null }, [
        "cloud_watch_logs_group_arn",
      ]),
      bucket(),
    );
    expect(statusOf("log/cloudtrail-accountability", input)).toBe("not_applicable");
  });

  // SF-2. A single-region trail is single-region whatever the other flag turns
  // out to be, so the evidenced failure must survive an unknown sibling.
  it("still fails a single-region trail when a sibling flag is unknown", () => {
    const input = model(
      trail({ is_multi_region_trail: false, include_global_service_events: null }, [
        "include_global_service_events",
      ]),
    );
    expect(statusOf("log/cloudtrail-multi-region", input)).toBe("fail");
  });

  // SF-3. Uncertainty about one bucket said nothing about any other, yet it
  // converted every subject's verdict to not-applicable.
  it("confines an unknown flag to the bucket it belongs to", () => {
    const input = model(
      resource("aws_s3_bucket.a", "aws_s3_bucket", { bucket: "a" }),
      resource("aws_s3_bucket.b", "aws_s3_bucket", { bucket: "b" }),
      resource(
        "aws_s3_bucket_public_access_block.b",
        "aws_s3_bucket_public_access_block",
        { bucket: "b", block_public_acls: null },
        ["block_public_acls"],
      ),
    );
    expect(statusesOf("ivs/s3-public-access-block", input)).toEqual(["fail", "not_applicable"]);
  });

  // SF-4. Only an explicit "egress" is safe to drop; anything else means we do
  // not know what we are looking at. The reason is asserted too: a bare status
  // check also passes when the rule is silently dropped and the check falls
  // back to "no ingress rules to inspect" — which is the bug, not the fix.
  it("is not_applicable, naming the rule, when a standalone rule's type is unknown", () => {
    const input = model(
      sgRule(
        { type: null, from_port: 22, to_port: 22, protocol: "tcp", cidr_blocks: ["0.0.0.0/0"] },
        ["type"],
      ),
    );
    const finding = run("ivs/no-open-admin-ports", input)[0];
    expect(finding?.status).toBe("not_applicable");
    expect(finding?.reason).toContain("aws_security_group_rule.r.type");
    expect(finding?.reason).toContain("not known until apply");
  });

  it("names the rule when its type is present but unrecognised", () => {
    const input = model(
      sgRule({
        type: "Ingress",
        from_port: 22,
        to_port: 22,
        protocol: "tcp",
        cidr_blocks: ["0.0.0.0/0"],
      }),
    );
    const finding = run("ivs/no-open-admin-ports", input)[0];
    expect(finding?.status).toBe("not_applicable");
    expect(finding?.reason).toContain("aws_security_group_rule.r.type");
    // Present-but-unrecognised is not unknown-until-apply, and the reason for
    // declining must not claim it is.
    expect(finding?.reason).toContain("could not be read");
    expect(finding?.reason).not.toContain("not known until apply");
  });

  // SF-5. A VPC created here whose default group is never adopted keeps the
  // rules AWS gave it, and the reason has to name the VPC.
  it("names a VPC whose default security group is never adopted", () => {
    const finding = run(
      "ivs/default-sg-locked-down",
      model(resource("aws_vpc.main", "aws_vpc", { id: "vpc-a" })),
    )[0];
    expect(finding?.status).toBe("not_applicable");
    expect(finding?.reason).toContain("aws_vpc.main");
  });

  it("stays silent about a VPC whose default group is adopted and locked", () => {
    const input = model(
      resource("aws_vpc.main", "aws_vpc", { id: "vpc-a" }),
      resource("aws_default_security_group.d", "aws_default_security_group", {
        vpc_id: "vpc-a",
        ingress: [],
        egress: [],
      }),
    );
    expect(statusesOf("ivs/default-sg-locked-down", input)).toEqual(["pass"]);
  });

  // FU-1. Defaulting a missing protocol to "-1" means *every protocol*, which
  // manufactured an "all ports open to the world" failure out of a gap. The
  // rule must be *reported*, not merely not-failed — so the reason is asserted.
  it("declines, naming the rule, when the protocol is missing", () => {
    const input = model(
      resource("aws_security_group.w", "aws_security_group", {
        ingress: [{ from_port: 443, to_port: 443, cidr_blocks: ["0.0.0.0/0"] }],
      }),
    );
    const finding = run("ivs/no-open-admin-ports", input)[0];
    expect(finding?.status).toBe("not_applicable");
    expect(finding?.reason).toContain("aws_security_group.w.ingress[0].protocol");
    // Absent is not unknown-until-apply, and the reason must not say it is.
    expect(finding?.reason).toContain("could not be read");
  });

  it("declines a TCP rule whose ports are absent, naming a port attribute", () => {
    const input = model(
      resource("aws_security_group.w", "aws_security_group", {
        ingress: [{ protocol: "tcp", cidr_blocks: ["0.0.0.0/0"] }],
      }),
    );
    const finding = run("ivs/no-open-admin-ports", input)[0];
    expect(finding?.status).toBe("not_applicable");
    // Naming the CIDR attribute here would point an auditor at a field that
    // was read perfectly well.
    expect(finding?.reason).toContain("from_port");
    expect(finding?.reason).not.toContain("cidr");
  });

  // FU-5. Ports only exist for TCP/UDP/SCTP. A protocol with no port concept
  // is legitimately declared without ports, and an unrecognised one must not
  // be assumed portless — that would exempt it from the check entirely.
  it("passes a world-open ESP rule that declares no ports", () => {
    const input = model(
      resource("aws_security_group.w", "aws_security_group", {
        ingress: [{ protocol: "esp", cidr_blocks: ["0.0.0.0/0"] }],
      }),
    );
    expect(statusOf("ivs/no-open-admin-ports", input)).toBe("pass");
  });

  it("declines a protocol it does not classify rather than exempting it", () => {
    const input = model(
      resource("aws_security_group.w", "aws_security_group", {
        ingress: [{ protocol: "tpc", from_port: 22, to_port: 22, cidr_blocks: ["0.0.0.0/0"] }],
      }),
    );
    const finding = run("ivs/no-open-admin-ports", input)[0];
    expect(finding?.status).toBe("not_applicable");
    expect(finding?.reason).toContain("does not classify");
  });

  it("reads a protocol given as an IANA number", () => {
    const input = model(
      resource("aws_security_group.w", "aws_security_group", {
        ingress: [{ protocol: 6, from_port: 22, to_port: 22, cidr_blocks: ["0.0.0.0/0"] }],
      }),
    );
    expect(statusOf("ivs/no-open-admin-ports", input)).toBe("fail");
  });

  it("fails a world-open rule whose protocol is the word all", () => {
    const input = model(
      resource("aws_security_group.w", "aws_security_group", {
        ingress: [{ protocol: "all", cidr_blocks: ["0.0.0.0/0"] }],
      }),
    );
    expect(statusOf("ivs/no-open-admin-ports", input)).toBe("fail");
  });

  // MB-A. An S3 bucket is named globally, so a satellite here can configure a
  // bucket created in another configuration — that satellite *is* the evidence.
  // Testing declaration before coverage reported "not declared here" while
  // holding the very evidence that contradicts it.
  it("passes LOG-02 when the log bucket's satellites are here but the bucket is not", () => {
    const input = model(
      trail({ s3_bucket_name: "logs", enable_log_file_validation: true }),
      sse(),
      fullBlock(),
    );
    const finding = run("log/cloudtrail-log-validation", input)[0];
    expect(finding?.status).toBe("pass");
    expect(finding?.evidence.map((item) => item.resourceAddress)).toContain(
      "aws_s3_bucket_server_side_encryption_configuration.logs",
    );
  });

  it("passes LOG-04 when only the access-logging resource is declared", () => {
    const input = model(
      trail({ s3_bucket_name: "logs" }),
      resource("aws_s3_bucket_logging.logs", "aws_s3_bucket_logging", { bucket: "logs" }),
    );
    expect(statusOf("log/cloudtrail-accountability", input)).toBe("pass");
  });

  // SF-C. Matching is by id, which a create plan does not know. Reporting a
  // VPC as unevidenceable while the group beside it just passed contradicts
  // the finding already made.
  it("does not contradict its own Pass on a create plan", () => {
    const input = model(
      resource("aws_vpc.main", "aws_vpc", { id: null }, ["id"]),
      resource(
        "aws_default_security_group.d",
        "aws_default_security_group",
        { vpc_id: null, ingress: [], egress: [] },
        ["vpc_id"],
      ),
    );
    expect(statusesOf("ivs/default-sg-locked-down", input)).toEqual(["pass"]);
  });

  // Pigeonhole: more VPCs than adopted groups means at least one is unmanaged,
  // whichever way they pair up. That much is evidenced even with unknown ids.
  it("counts unadopted groups when ids cannot be matched", () => {
    const input = model(
      resource("aws_vpc.a", "aws_vpc", { id: null }, ["id"]),
      resource("aws_vpc.b", "aws_vpc", { id: null }, ["id"]),
      resource(
        "aws_default_security_group.d",
        "aws_default_security_group",
        { vpc_id: null, ingress: [], egress: [] },
        ["vpc_id"],
      ),
    );
    expect(statusesOf("ivs/default-sg-locked-down", input)).toEqual(["pass", "not_applicable"]);
  });

  // SF-D. "has no CloudWatch Logs group" is an assertion of absence, and an
  // unknown ARN does not support it.
  it("does not claim the CloudWatch group is absent when it is merely unknown", () => {
    const input = model(
      trail({ s3_bucket_name: "elsewhere", cloud_watch_logs_group_arn: null }, [
        "cloud_watch_logs_group_arn",
      ]),
    );
    const finding = run("log/cloudtrail-accountability", input)[0];
    expect(finding?.status).toBe("not_applicable");
    expect(finding?.reason).toContain("not known until apply");
    expect(finding?.reason).not.toContain("has no CloudWatch Logs group");
  });

  // FU-2. A present-but-unreadable value is not an absent one, and failing on
  // it would record `observed: null` for an input that plainly set something.
  it("declines rather than failing on a non-string CloudWatch ARN", () => {
    const input = model(
      trail({ s3_bucket_name: "b", cloud_watch_logs_group_arn: 12 }),
      bucket("b"),
    );
    expect(statusOf("log/cloudtrail-accountability", input)).toBe("not_applicable");
  });

  // FU-2. "no rules" is an assertion, and a non-list value does not support it.
  it("declines a default security group whose ingress is not a list", () => {
    const input = model(
      resource("aws_default_security_group.d", "aws_default_security_group", {
        ingress: "all",
        egress: [],
      }),
    );
    expect(statusOf("ivs/default-sg-locked-down", input)).toBe("not_applicable");
  });

  // FU-3. Aurora puts the endpoint on the cluster's instances.
  it("fails a publicly accessible Aurora cluster instance", () => {
    const input = model(
      resource("aws_rds_cluster_instance.a", "aws_rds_cluster_instance", {
        publicly_accessible: true,
      }),
    );
    expect(statusOf("ivs/s3-public-access-block", input)).toBe("fail");
  });

  // L01. The guard that stops an unknown trail-side flag becoming a Fail on
  // the bucket's behalf — the exact failure mode this milestone is about.
  it("declines when log-file validation is unknown and the bucket is unprotected", () => {
    const input = model(
      trail({ s3_bucket_name: "logs", enable_log_file_validation: null }, [
        "enable_log_file_validation",
      ]),
      bucket(),
    );
    expect(statusOf("log/cloudtrail-log-validation", input)).toBe("not_applicable");
  });

  // I14. The partial-block case was pinned only under the LOG check, leaving
  // the control whose headline promise it is unguarded.
  it("fails a three-of-four public-access block under its own control", () => {
    const input = model(
      bucket(),
      resource("aws_s3_bucket_public_access_block.logs", "aws_s3_bucket_public_access_block", {
        bucket: "logs",
        block_public_acls: true,
        block_public_policy: true,
        ignore_public_acls: true,
        restrict_public_buckets: false,
      }),
    );
    expect(statusOf("ivs/s3-public-access-block", input)).toBe("fail");
  });
});

describe("regressions found by the M4 third review round", () => {
  // MB-1. `""` is how Terraform serialises an unset optional string, both from
  // `variable "x" { default = "" }` and from state. Reading it as a value made
  // LOG-04 report Pass with `observed: ""` — a Pass with nothing behind it.
  it("fails a trail whose CloudWatch ARN is the empty string", () => {
    const input = model(
      trail({ s3_bucket_name: "logs", cloud_watch_logs_group_arn: "" }),
      bucket(),
    );
    expect(statusOf("log/cloudtrail-accountability", input)).toBe("fail");
  });

  // An empty string is a definite "unset", unlike a value we cannot interpret,
  // so it must not be softened into not-applicable either.
  it("treats an empty ARN as absent rather than unreadable", () => {
    const finding = run(
      "log/cloudtrail-accountability",
      model(trail({ s3_bucket_name: "elsewhere", cloud_watch_logs_group_arn: "" })),
    )[0];
    expect(finding?.reason).toContain("has no CloudWatch Logs group");
  });

  // The same root cause reached every correlation key.
  it("does not correlate a bucket whose name is the empty string", () => {
    const input = model(
      resource("aws_s3_bucket.a", "aws_s3_bucket", { bucket: "" }),
      resource("aws_s3_bucket_public_access_block.a", "aws_s3_bucket_public_access_block", {
        bucket: "",
        block_public_acls: true,
        block_public_policy: true,
        ignore_public_acls: true,
        restrict_public_buckets: true,
      }),
    );
    expect(statusOf("ivs/s3-public-access-block", input)).toBe("not_applicable");
  });

  // SF-3 / M2. The bucket is cited in preference to its satellites when it is
  // declared, and each resource is described as what it actually is: a
  // satellite configures the bucket, it does not hold the logs.
  it("cites the bucket and every satellite that evidenced LOG-02", () => {
    const input = model(
      trail({ s3_bucket_name: "logs", enable_log_file_validation: true }),
      bucket(),
      sse(),
      fullBlock(),
    );
    const evidence = run("log/cloudtrail-log-validation", input)[0]?.evidence ?? [];
    const cited = evidence.map((item) => item.resourceAddress);
    expect(cited).toContain("aws_s3_bucket.logs");
    expect(cited).toContain("aws_s3_bucket_server_side_encryption_configuration.logs");
    expect(cited).toContain("aws_s3_bucket_public_access_block.logs");

    const bucketEntry = evidence.find((item) => item.resourceAddress === "aws_s3_bucket.logs");
    expect(String(bucketEntry?.observed)).toContain("holds the logs");
    const satellite = evidence.find((item) =>
      item.resourceAddress.startsWith("aws_s3_bucket_server_side"),
    );
    // The SSE configuration does not hold anything.
    expect(String(satellite?.observed)).not.toContain("holds the logs");
  });

  // SF-2 / case D. A group adopting a VPC that is not declared here offsets
  // nothing: the VPC that *is* declared still has an unmanaged default group.
  it("does not let a group adopting an external VPC offset a declared one", () => {
    const input = model(
      resource("aws_vpc.a", "aws_vpc", { id: null }, ["id"]),
      resource("aws_default_security_group.d", "aws_default_security_group", {
        vpc_id: "vpc-somewhere-else",
        ingress: [],
        egress: [],
      }),
    );
    expect(statusesOf("ivs/default-sg-locked-down", input)).toEqual(["pass", "not_applicable"]);
  });

  // SF-1 / M14. The reason must name the side that actually failed to resolve,
  // and must not claim "not known until apply" of ids that are merely absent.
  it("says which side could not be resolved", () => {
    const input = model(
      resource("aws_vpc.a", "aws_vpc", { id: "vpc-a" }),
      resource("aws_vpc.b", "aws_vpc", { id: "vpc-b" }),
      resource("aws_default_security_group.d", "aws_default_security_group", {
        vpc_id: 42,
        ingress: [],
        egress: [],
      }),
    );
    const finding = run("ivs/default-sg-locked-down", input).find(
      (item) => item.status === "not_applicable",
    );
    expect(finding?.reason).toContain("could not be read");
    expect(finding?.reason).not.toContain("not known until apply");
  });

  // M22. The counting reason is the whole content of that verdict.
  it("explains the count when ids cannot be matched", () => {
    const input = model(
      resource("aws_vpc.a", "aws_vpc", { id: null }, ["id"]),
      resource("aws_vpc.b", "aws_vpc", { id: null }, ["id"]),
      resource(
        "aws_default_security_group.d",
        "aws_default_security_group",
        { vpc_id: null, ingress: [], egress: [] },
        ["vpc_id"],
      ),
    );
    const finding = run("ivs/default-sg-locked-down", input).find(
      (item) => item.status === "not_applicable",
    );
    expect(finding?.reason).toContain("2 VPC(s)");
    expect(finding?.reason).toContain("not known until apply");
  });

  // M18. LOG-07's not-applicable wording is the only thing distinguishing
  // "nothing is unmet but something is unknown" from an unexamined control.
  it("says nothing else is non-compliant when a trail flag is unknown", () => {
    const finding = run(
      "log/cloudtrail-multi-region",
      model(
        trail({ is_multi_region_trail: true, include_global_service_events: null }, [
          "include_global_service_events",
        ]),
      ),
    )[0];
    expect(finding?.reason).toContain("aws_cloudtrail.main.include_global_service_events");
    expect(finding?.reason).toContain("Nothing else read from this trail is non-compliant");
  });

  // M21. The allowlist is matched lowercase, so casing must be normalised or
  // every capitalised protocol would be declined as unrecognised.
  for (const protocol of ["TCP", "Tcp"]) {
    it(`reads protocol "${protocol}" case-insensitively`, () => {
      const input = model(
        resource("aws_security_group.w", "aws_security_group", {
          ingress: [{ protocol, from_port: 22, to_port: 22, cidr_blocks: ["0.0.0.0/0"] }],
        }),
      );
      expect(statusOf("ivs/no-open-admin-ports", input)).toBe("fail");
    });
  }

  it("trims a padded protocol", () => {
    const input = model(
      resource("aws_security_group.w", "aws_security_group", {
        ingress: [{ protocol: " tcp ", from_port: 22, to_port: 22, cidr_blocks: ["0.0.0.0/0"] }],
      }),
    );
    expect(statusOf("ivs/no-open-admin-ports", input)).toBe("fail");
  });

  // FU-1. The newer resource type calls it `ip_protocol`; naming `protocol`
  // would point an auditor at an attribute that does not exist on it.
  it("names ip_protocol on the resource type that uses that name", () => {
    const input = model(
      resource("aws_vpc_security_group_ingress_rule.in", "aws_vpc_security_group_ingress_rule", {
        ip_protocol: "tpc",
        from_port: 22,
        to_port: 22,
        cidr_ipv4: "0.0.0.0/0",
      }),
    );
    const finding = run("ivs/no-open-admin-ports", input)[0];
    expect(finding?.reason).toContain("ip_protocol");
    expect(finding?.reason).not.toContain(".protocol");
  });

  // FU-2. Portless protocols a VPN or transit setup declares must not become
  // noise, and none of them can reach a TCP port anyway.
  for (const protocol of ["ipv6-icmp", "ospf", "4", "41"]) {
    it(`accepts portless protocol "${protocol}" without ports`, () => {
      const input = model(
        resource("aws_security_group.w", "aws_security_group", {
          ingress: [{ protocol, cidr_blocks: ["0.0.0.0/0"] }],
        }),
      );
      expect(statusOf("ivs/no-open-admin-ports", input)).toBe("pass");
    });
  }

  it("fails world-open UDP-Lite on a sensitive port", () => {
    const input = model(
      resource("aws_security_group.w", "aws_security_group", {
        ingress: [{ protocol: "136", from_port: 22, to_port: 22, cidr_blocks: ["0.0.0.0/0"] }],
      }),
    );
    expect(statusOf("ivs/no-open-admin-ports", input)).toBe("fail");
  });

  // An unrecognised rule must not suppress a real finding beside it.
  it("still reports a real failure alongside an unrecognised rule", () => {
    const input = model(
      resource("aws_security_group.w", "aws_security_group", {
        ingress: [
          { protocol: "tpc", from_port: 80, to_port: 80, cidr_blocks: ["0.0.0.0/0"] },
          { protocol: "tcp", from_port: 22, to_port: 22, cidr_blocks: ["0.0.0.0/0"] },
        ],
      }),
    );
    expect([...statusesOf("ivs/no-open-admin-ports", input)].sort()).toEqual([
      "fail",
      "not_applicable",
    ]);
  });
});

describe("regressions found by the M4 fourth review round", () => {
  // MB-A. Narrowing asText made an empty correlator "unreadable", which
  // blocked every subject of that type — one malformed satellite turned every
  // evidenced Fail in the input into a not-applicable. A key that is empty or
  // absent names no subject and never will, so it is evidence about none.
  it("still fails an uncovered bucket when another satellite's key is empty", () => {
    const input = model(
      resource("aws_s3_bucket.plain", "aws_s3_bucket", { bucket: "plain" }),
      resource("aws_s3_bucket_public_access_block.broken", "aws_s3_bucket_public_access_block", {
        bucket: "",
        block_public_acls: true,
      }),
    );
    const finding = run("ivs/s3-public-access-block", input)[0];
    expect(finding?.status).toBe("fail");
  });

  it("still fails an uncovered VPC when another flow log's vpc_id is empty", () => {
    const input = model(
      resource("aws_vpc.main", "aws_vpc", { id: "vpc-a" }),
      resource("aws_flow_log.broken", "aws_flow_log", { vpc_id: "" }),
    );
    expect(statusOf("log/vpc-flow-logs", input)).toBe("fail");
  });

  // An unknown correlator is different in kind: it may still turn out to name
  // this subject, so it must keep blocking.
  it("still declines when another satellite's key is unknown until apply", () => {
    const input = model(
      resource("aws_s3_bucket.plain", "aws_s3_bucket", { bucket: "plain" }),
      resource(
        "aws_s3_bucket_public_access_block.pending",
        "aws_s3_bucket_public_access_block",
        { bucket: null },
        ["bucket"],
      ),
    );
    expect(statusOf("ivs/s3-public-access-block", input)).toBe("not_applicable");
  });

  // SF-D. Whitespace is MB-1 with spaces instead of nothing.
  it("fails a trail whose CloudWatch ARN is only whitespace", () => {
    const input = model(
      trail({ s3_bucket_name: "logs", cloud_watch_logs_group_arn: "   " }),
      bucket(),
    );
    expect(statusOf("log/cloudtrail-accountability", input)).toBe("fail");
  });

  // SF-C. Two trails sharing a log bucket must not produce byte-identical
  // verdicts, and the CloudWatch half must be shown as examined.
  it("names the trail in LOG-04's evidence, not only the bucket's satellite", () => {
    const input = model(
      trail({ s3_bucket_name: "logs" }),
      bucket(),
      resource("aws_s3_bucket_logging.logs", "aws_s3_bucket_logging", { bucket: "logs" }),
    );
    const evidence = run("log/cloudtrail-accountability", input)[0]?.evidence ?? [];
    const cited = evidence.map((item) => item.resourceAddress);
    expect(cited).toContain("aws_cloudtrail.main");
    expect(cited).toContain("aws_s3_bucket_logging.logs");
  });

  // M5. Every satellite is kept, not just the last one seen.
  it("cites every satellite when two configure the same subject", () => {
    const input = model(
      trail({ s3_bucket_name: "logs" }),
      bucket(),
      resource("aws_s3_bucket_logging.a", "aws_s3_bucket_logging", { bucket: "logs" }),
      resource("aws_s3_bucket_logging.b", "aws_s3_bucket_logging", { bucket: "logs" }),
    );
    const cited = (run("log/cloudtrail-accountability", input)[0]?.evidence ?? []).map(
      (item) => item.resourceAddress,
    );
    expect(cited).toContain("aws_s3_bucket_logging.a");
    expect(cited).toContain("aws_s3_bucket_logging.b");
  });

  // M4. A satellite is never described as holding the logs.
  it("does not describe a satellite as holding the logs when the bucket is elsewhere", () => {
    const input = model(
      trail({ s3_bucket_name: "logs", enable_log_file_validation: true }),
      sse(),
      fullBlock(),
    );
    const evidence = run("log/cloudtrail-log-validation", input)[0]?.evidence ?? [];
    for (const item of evidence.filter((entry) => entry.attribute === "bucket")) {
      expect(String(item.observed)).not.toContain("holds the logs");
    }
  });

  // SF-A. Two groups adopting one VPC cover one VPC between them.
  it("does not let two groups adopting the same VPC absorb a second VPC", () => {
    const input = model(
      resource("aws_vpc.a", "aws_vpc", { id: "vpc-a" }),
      resource("aws_vpc.b", "aws_vpc", { id: null }, ["id"]),
      resource("aws_default_security_group.one", "aws_default_security_group", {
        vpc_id: "vpc-a",
        ingress: [],
        egress: [],
      }),
      resource("aws_default_security_group.two", "aws_default_security_group", {
        vpc_id: "vpc-a",
        ingress: [],
        egress: [],
      }),
    );
    expect(statusesOf("ivs/default-sg-locked-down", input)).toEqual([
      "pass",
      "pass",
      "not_applicable",
    ]);
  });

  // M10. A group adopting a declared VPC does offset it.
  it("lets a group adopting a declared VPC offset that VPC", () => {
    const input = model(
      resource("aws_vpc.a", "aws_vpc", { id: "vpc-a" }),
      resource("aws_vpc.b", "aws_vpc", { id: null }, ["id"]),
      resource("aws_default_security_group.one", "aws_default_security_group", {
        vpc_id: "vpc-a",
        ingress: [],
        egress: [],
      }),
      resource(
        "aws_default_security_group.two",
        "aws_default_security_group",
        { vpc_id: null, ingress: [], egress: [] },
        ["vpc_id"],
      ),
    );
    expect(statusesOf("ivs/default-sg-locked-down", input)).toEqual(["pass", "pass"]);
  });

  // SF-B. vpc_id is Optional — omitting it adopts the default VPC's group, so
  // the reason must not call that unreadable.
  it("says a group declares no vpc_id rather than calling it unreadable", () => {
    const input = model(
      resource("aws_vpc.a", "aws_vpc", { id: "vpc-a" }),
      resource("aws_vpc.b", "aws_vpc", { id: "vpc-b" }),
      resource("aws_default_security_group.one", "aws_default_security_group", {
        ingress: [],
        egress: [],
      }),
    );
    const finding = run("ivs/default-sg-locked-down", input).find(
      (item) => item.status === "not_applicable",
    );
    expect(finding?.reason).toContain("declares no vpc_id");
    expect(finding?.reason).not.toContain("could not be read");
  });
});

/** The three sentences the fifth round found false in otherwise-correct output. */
describe("reasons and evidence say what is true", () => {
  // S-1. `offsetting` counts VPCs covered, not groups declared.
  it("counts VPCs covered, not security groups, in the IVS-06 reason", () => {
    const input = model(
      resource("aws_vpc.a", "aws_vpc", { id: "vpc-a" }),
      resource("aws_vpc.b", "aws_vpc", { id: null }, ["id"]),
      resource("aws_vpc.c", "aws_vpc", { id: "vpc-c" }),
      resource("aws_default_security_group.one", "aws_default_security_group", {
        vpc_id: "vpc-a",
        ingress: [],
        egress: [],
      }),
      resource("aws_default_security_group.two", "aws_default_security_group", {
        vpc_id: "vpc-a",
        ingress: [],
        egress: [],
      }),
    );
    const finding = run("ivs/default-sg-locked-down", input).find(
      (item) => item.status === "not_applicable",
    );
    expect(finding?.reason).toContain("3 VPC(s) but only 1 of them are covered");
  });

  // S-2. `observed: null` asserts the attribute is unset, which is false of a
  // value that is present but unreadable.
  it("does not record a present-but-unreadable ARN as null", () => {
    const input = model(
      trail({ s3_bucket_name: "logs", cloud_watch_logs_group_arn: 42 }),
      bucket(),
      resource("aws_s3_bucket_logging.logs", "aws_s3_bucket_logging", { bucket: "logs" }),
    );
    const finding = run("log/cloudtrail-accountability", input)[0];
    expect(finding?.status).toBe("pass");
    const arn = finding?.evidence.find((item) => item.attribute === "cloud_watch_logs_group_arn");
    expect(arn?.observed).toBe("present but could not be read");
  });

  // S-3. A plaintext listener is declared; declining to inspect it is not the
  // same as the input declaring nothing.
  it("does not claim there is nothing to inspect when a listener was skipped", () => {
    const input = model(
      resource("aws_lb_listener.plain", "aws_lb_listener", { port: 80, protocol: "HTTP" }),
    );
    const finding = run("cek/approved-algorithms", input)[0];
    expect(finding?.status).toBe("not_applicable");
    expect(finding?.reason).toContain("1 load-balancer listener(s) select no TLS policy");
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
