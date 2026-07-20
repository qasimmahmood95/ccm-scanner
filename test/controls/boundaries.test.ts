import { describe, expect, it } from "vitest";
import type { Resource, ResourceModel, Status } from "../../src/index.js";
import { model, resource, run, statusOf } from "../support/checks.js";

/**
 * Unit tests at the discriminating boundary of each check.
 *
 * The fixture lane proves the checks work end to end, but it cannot reach the
 * cases that distinguish a correct check from a subtly wrong one — an
 * unknown-until-apply correlator, an inverted matcher, a condition with the
 * wrong sense, an unrecognised TLS policy. Those are exactly where the false
 * verdicts lived, so each is pinned here: revert any of those fixes and a test
 * fails.
 */

function policyResource(address: string, document: unknown, unknown = false): Resource {
  return resource(
    address,
    "aws_iam_policy",
    { policy: typeof document === "string" ? document : JSON.stringify(document) },
    unknown ? ["policy"] : [],
  );
}

function statement(extra: Record<string, unknown>): Record<string, unknown> {
  return { Version: "2012-10-17", Statement: [{ Effect: "Allow", ...extra }] };
}

describe("iam/no-wildcard-allow", () => {
  const cases: readonly [string, unknown, Status][] = [
    ["wildcard action and resource", statement({ Action: "*", Resource: "*" }), "fail"],
    [
      "scoped action and resource",
      statement({ Action: "s3:GetObject", Resource: "arn:x" }),
      "pass",
    ],
    // Both halves are required: a scoped action on every resource is the
    // ordinary shape of a legitimate policy.
    ["scoped action, wildcard resource", statement({ Action: "s3:Get*", Resource: "*" }), "pass"],
    ["wildcard action, scoped resource", statement({ Action: "*", Resource: "arn:x" }), "pass"],
    // Inverted matchers grant everything except what they list.
    ["NotAction", statement({ NotAction: ["iam:*"], Resource: "*" }), "not_applicable"],
    ["NotResource", statement({ Action: "*", NotResource: ["arn:x"] }), "not_applicable"],
    // The parser accepts lowercase keys, so it must not compare the value
    // case-sensitively.
    [
      "lowercase keys and effect",
      { Version: "2012-10-17", Statement: [{ effect: "allow", action: "*", resource: "*" }] },
      "fail",
    ],
    [
      "deny is not a grant",
      { Statement: [{ Effect: "Deny", Action: "*", Resource: "*" }] },
      "pass",
    ],
    // Reading a lowercase Deny as an Allow would invent a failure.
    ["lowercase deny", { Statement: [{ effect: "deny", action: "*", resource: "*" }] }, "pass"],
    ["no Statement key at all", { Version: "2012-10-17" }, "not_applicable"],
    ["no statements", { Version: "2012-10-17", Statement: [] }, "not_applicable"],
    ["unparseable", "{not json", "not_applicable"],
  ];

  for (const [name, document, expected] of cases) {
    it(`is ${expected} for ${name}`, () => {
      expect(
        statusOf("iam/no-wildcard-allow", model(policyResource("aws_iam_policy.p", document))),
      ).toBe(expected);
    });
  }

  it("is not_applicable when the document is not known until apply", () => {
    const input = model(policyResource("aws_iam_policy.p", statement({}), true));
    expect(statusOf("iam/no-wildcard-allow", input)).toBe("not_applicable");
  });

  // Both yield not_applicable, so only the reason distinguishes them — and the
  // reason is what an auditor reads.
  it("says why it declined: unreadable versus simply empty", () => {
    const missing = run(
      "iam/no-wildcard-allow",
      model(policyResource("aws_iam_policy.p", { Version: "2012-10-17" })),
    )[0]?.reason;
    const empty = run(
      "iam/no-wildcard-allow",
      model(policyResource("aws_iam_policy.p", { Version: "2012-10-17", Statement: [] })),
    )[0]?.reason;

    expect(missing).toContain("could not be parsed");
    expect(empty).toContain("declares no statements");
  });
});

describe("iam/no-wildcard-trust", () => {
  function role(trust: unknown): ResourceModel {
    return model(
      resource("aws_iam_role.r", "aws_iam_role", { assume_role_policy: JSON.stringify(trust) }),
    );
  }

  it("fails an unconditioned wildcard principal", () => {
    expect(
      statusOf("iam/no-wildcard-trust", role({ Statement: [{ Effect: "Allow", Principal: "*" }] })),
    ).toBe("fail");
  });

  it("fails the AWS-keyed wildcard form", () => {
    expect(
      statusOf(
        "iam/no-wildcard-trust",
        role({ Statement: [{ Effect: "Allow", Principal: { AWS: "*" } }] }),
      ),
    ).toBe("fail");
  });

  // A condition that constrains something other than the principal leaves the
  // role open; saying "pass" there was a one-line policy edit away from a lie.
  it("is not_applicable for a wildcard principal under a non-principal condition", () => {
    expect(
      statusOf(
        "iam/no-wildcard-trust",
        role({
          Statement: [
            {
              Effect: "Allow",
              Principal: "*",
              Condition: { Bool: { "aws:SecureTransport": "true" } },
            },
          ],
        }),
      ),
    ).toBe("not_applicable");
  });

  it("passes a wildcard principal constrained by organisation", () => {
    expect(
      statusOf(
        "iam/no-wildcard-trust",
        role({
          Statement: [
            {
              Effect: "Allow",
              Principal: "*",
              Condition: { StringEquals: { "aws:PrincipalOrgID": "o-abc123" } },
            },
          ],
        }),
      ),
    ).toBe("pass");
  });

  it("passes a service principal", () => {
    expect(
      statusOf(
        "iam/no-wildcard-trust",
        role({ Statement: [{ Effect: "Allow", Principal: { Service: "ec2.amazonaws.com" } }] }),
      ),
    ).toBe("pass");
  });

  it("fails an any-account root principal", () => {
    expect(
      statusOf(
        "iam/no-wildcard-trust",
        role({
          Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::*:root" } }],
        }),
      ),
    ).toBe("fail");
  });

  // Named explicitly in the mapping row, so it must stay pinned.
  it("passes an external-id condition", () => {
    expect(
      statusOf(
        "iam/no-wildcard-trust",
        role({
          Statement: [
            {
              Effect: "Allow",
              Principal: "*",
              Condition: { StringEquals: { "sts:ExternalId": "shared-secret-id" } },
            },
          ],
        }),
      ),
    ).toBe("pass");
  });

  // aws:PrincipalArn is present on every authenticated request, so IfExists
  // behaves like its base operator here — rejecting it would invent an NA.
  it("passes an IfExists condition on an always-present key", () => {
    expect(
      statusOf(
        "iam/no-wildcard-trust",
        role({
          Statement: [
            {
              Effect: "Allow",
              Principal: "*",
              Condition: {
                ArnLikeIfExists: { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/app" },
              },
            },
          ],
        }),
      ),
    ).toBe("pass");
  });

  it("passes a specific source CIDR", () => {
    expect(
      statusOf(
        "iam/no-wildcard-trust",
        role({
          Statement: [
            {
              Effect: "Allow",
              Principal: "*",
              Condition: { IpAddress: { "aws:SourceIp": "203.0.113.0/24" } },
            },
          ],
        }),
      ),
    ).toBe("pass");
  });

  it("passes a principal tag condition, which AWS always writes with a key suffix", () => {
    expect(
      statusOf(
        "iam/no-wildcard-trust",
        role({
          Statement: [
            {
              Effect: "Allow",
              Principal: "*",
              Condition: { StringEquals: { "aws:PrincipalTag/team": "platform" } },
            },
          ],
        }),
      ),
    ).toBe("pass");
  });

  // Naming a constraining key is not the same as constraining. Each of these
  // would be a Pass on the check whose whole purpose is catching roles anyone
  // can assume.
  const vacuous: readonly [string, Record<string, unknown>][] = [
    ["a negated organisation match", { StringNotEquals: { "aws:PrincipalOrgID": "o-abc123" } }],
    ["a presence test", { Null: { "aws:PrincipalOrgID": "true" } }],
    ["a negated ARN match", { ArnNotLike: { "aws:PrincipalArn": "arn:aws:iam::1:role/admin" } }],
    ["an any-account ARN pattern", { StringLike: { "aws:PrincipalArn": "arn:aws:iam::*:role/*" } }],
    ["a wildcard value", { StringEquals: { "aws:PrincipalAccount": "*" } }],
    ["an open CIDR", { IpAddress: { "aws:SourceIp": "0.0.0.0/0" } }],
    ["a negated CIDR", { NotIpAddress: { "aws:SourceIp": "10.0.0.0/8" } }],
    // AWS ORs the values of one key, so the union is as wide as its widest
    // member: adding a narrow value beside an open one must not improve the
    // verdict.
    [
      "an open CIDR beside a real one",
      { IpAddress: { "aws:SourceIp": ["0.0.0.0/0", "203.0.113.0/24"] } },
    ],
    [
      "an any-account ARN beside a specific one",
      {
        StringLike: {
          "aws:PrincipalArn": ["arn:aws:iam::*:role/*", "arn:aws:iam::123456789012:role/app"],
        },
      },
    ],
    // ...IfExists is true when the key is absent, and these keys are absent for
    // whole classes of principal — an account outside any organisation, a
    // caller not coming via a VPC endpoint, an assumed role with no username.
    ["an IfExists org guard", { StringEqualsIfExists: { "aws:PrincipalOrgID": "o-abc123" } }],
    ["an IfExists VPC-endpoint guard", { StringEqualsIfExists: { "aws:SourceVpce": "vpce-1" } }],
    ["an IfExists source-IP guard", { IpAddressIfExists: { "aws:SourceIp": "203.0.113.0/24" } }],
    ["an IfExists source-ARN guard", { ArnEqualsIfExists: { "aws:SourceArn": "arn:aws:s3:::b" } }],
    ["an IfExists username guard", { StringEqualsIfExists: { "aws:username": "alice" } }],
    ["an IfExists external-id guard", { StringEqualsIfExists: { "sts:ExternalId": "shared" } }],
    // An empty value list constrains nothing.
    ["an empty value list", { StringEquals: { "aws:PrincipalOrgID": [] } }],
  ];
  for (const [name, condition] of vacuous) {
    it(`is not_applicable for a wildcard principal under ${name}`, () => {
      expect(
        statusOf(
          "iam/no-wildcard-trust",
          role({ Statement: [{ Effect: "Allow", Principal: "*", Condition: condition }] }),
        ),
      ).toBe("not_applicable");
    });
  }
});

describe("iam/mfa-enforcement-present", () => {
  const cases: readonly [string, string, Record<string, unknown>, Status][] = [
    ["Deny when MFA absent", "Deny", { Bool: { "aws:MultiFactorAuthPresent": "false" } }, "pass"],
    ["Allow only with MFA", "Allow", { Bool: { "aws:MultiFactorAuthPresent": "true" } }, "pass"],
    ["Deny with Null true", "Deny", { Null: { "aws:MultiFactorAuthPresent": "true" } }, "pass"],
    // Each of these mentions the key but does the opposite of enforcing it.
    [
      "Deny when MFA present",
      "Deny",
      { Bool: { "aws:MultiFactorAuthPresent": "true" } },
      "not_applicable",
    ],
    [
      "Allow when MFA absent",
      "Allow",
      { Bool: { "aws:MultiFactorAuthPresent": "false" } },
      "not_applicable",
    ],
    [
      "Allow when the key is null",
      "Allow",
      { Null: { "aws:MultiFactorAuthPresent": "true" } },
      "not_applicable",
    ],
    [
      "an operator that says nothing",
      "Deny",
      { StringEquals: { "aws:MultiFactorAuthPresent": "false" } },
      "not_applicable",
    ],
    // Policy authors write booleans in either case; the parser lowercases
    // values so the comparison must not be case-sensitive.
    [
      "a capitalised boolean value",
      "Deny",
      { Bool: { "aws:MultiFactorAuthPresent": "False" } },
      "pass",
    ],
  ];

  for (const [name, effect, condition, expected] of cases) {
    it(`is ${expected} for ${name}`, () => {
      const document = {
        Statement: [{ Effect: effect, Action: "*", Resource: "*", Condition: condition }],
      };
      expect(
        statusOf(
          "iam/mfa-enforcement-present",
          model(policyResource("aws_iam_policy.p", document)),
        ),
      ).toBe(expected);
    });
  }
});

describe("password policy thresholds", () => {
  const strong = {
    minimum_password_length: 14,
    require_uppercase_characters: true,
    require_lowercase_characters: true,
    require_numbers: true,
    require_symbols: true,
    password_reuse_prevention: 24,
    max_password_age: 90,
  };

  function policy(overrides: Record<string, unknown>): ResourceModel {
    return model(
      resource("aws_iam_account_password_policy.p", "aws_iam_account_password_policy", {
        ...strong,
        ...overrides,
      }),
    );
  }

  // Each threshold is pinned individually; violating several at once would let
  // any one of them be removed unnoticed.
  const strength: readonly [string, Record<string, unknown>, Status][] = [
    ["at the length boundary", { minimum_password_length: 14 }, "pass"],
    ["one below the length boundary", { minimum_password_length: 13 }, "fail"],
    ["without uppercase", { require_uppercase_characters: false }, "fail"],
    ["without lowercase", { require_lowercase_characters: false }, "fail"],
    ["without numbers", { require_numbers: false }, "fail"],
    ["without symbols", { require_symbols: false }, "fail"],
  ];
  for (const [name, overrides, expected] of strength) {
    it(`iam/account-password-policy is ${expected} ${name}`, () => {
      expect(statusOf("iam/account-password-policy", policy(overrides))).toBe(expected);
    });
  }

  const lifecycle: readonly [string, Record<string, unknown>, Status][] = [
    ["at the reuse boundary", { password_reuse_prevention: 24 }, "pass"],
    ["one below the reuse boundary", { password_reuse_prevention: 23 }, "fail"],
    ["at the age boundary", { max_password_age: 90 }, "pass"],
    ["one past the age boundary", { max_password_age: 91 }, "fail"],
    ["with no expiry at all", { max_password_age: 0 }, "fail"],
  ];
  for (const [name, overrides, expected] of lifecycle) {
    it(`iam/password-lifecycle is ${expected} ${name}`, () => {
      expect(statusOf("iam/password-lifecycle", policy(overrides))).toBe(expected);
    });
  }
});

describe("cek/approved-algorithms", () => {
  function listener(sslPolicy: string): ResourceModel {
    return model(resource("aws_lb_listener.l", "aws_lb_listener", { ssl_policy: sslPolicy }));
  }

  it("passes a TLS 1.2+ policy", () => {
    expect(statusOf("cek/approved-algorithms", listener("ELBSecurityPolicy-TLS-1-2-2017-01"))).toBe(
      "pass",
    );
  });

  it("fails a policy known to permit TLS 1.0", () => {
    expect(
      statusOf("cek/approved-algorithms", listener("ELBSecurityPolicy-TLS13-1-0-2021-06")),
    ).toBe("fail");
  });

  it("fails the ELB default, which permits TLS 1.0", () => {
    expect(statusOf("cek/approved-algorithms", listener("ELBSecurityPolicy-2016-08"))).toBe("fail");
  });

  // An allowlist must not approve what it has never heard of.
  it("is not_applicable for an unrecognised policy", () => {
    expect(statusOf("cek/approved-algorithms", listener("ELBSecurityPolicy-Invented-2030"))).toBe(
      "not_applicable",
    );
  });

  it("fails a disallowed SSE algorithm", () => {
    const config = resource(
      "aws_s3_bucket_server_side_encryption_configuration.c",
      "aws_s3_bucket_server_side_encryption_configuration",
      {
        bucket: "b",
        rule: [{ apply_server_side_encryption_by_default: [{ sse_algorithm: "AES128" }] }],
      },
    );
    expect(statusOf("cek/approved-algorithms", model(config))).toBe("fail");
  });

  // The most common real-world setting; a regression here would false-fail
  // most estates.
  it("passes SSE-S3 (AES256)", () => {
    const config = resource(
      "aws_s3_bucket_server_side_encryption_configuration.c",
      "aws_s3_bucket_server_side_encryption_configuration",
      {
        bucket: "b",
        rule: [{ apply_server_side_encryption_by_default: [{ sse_algorithm: "AES256" }] }],
      },
    );
    expect(statusOf("cek/approved-algorithms", model(config))).toBe("pass");
  });

  it("passes an approved SSE algorithm", () => {
    const config = resource(
      "aws_s3_bucket_server_side_encryption_configuration.c",
      "aws_s3_bucket_server_side_encryption_configuration",
      {
        bucket: "b",
        rule: [{ apply_server_side_encryption_by_default: [{ sse_algorithm: "aws:kms" }] }],
      },
    );
    expect(statusOf("cek/approved-algorithms", model(config))).toBe("pass");
  });
});

describe("cek/tls-enforced", () => {
  const bucket = resource("aws_s3_bucket.b", "aws_s3_bucket", { bucket: "b" });

  function withPolicy(document: unknown, unknown = false): ResourceModel {
    return model(
      bucket,
      resource(
        "aws_s3_bucket_policy.p",
        "aws_s3_bucket_policy",
        {
          bucket: "b",
          policy: typeof document === "string" ? document : JSON.stringify(document),
        },
        unknown ? ["policy"] : [],
      ),
    );
  }

  function deny(overrides: Record<string, unknown> = {}): unknown {
    return {
      Statement: [
        {
          Effect: "Deny",
          Principal: "*",
          Action: "s3:*",
          Resource: "arn:aws:s3:::b/*",
          Condition: { Bool: { "aws:SecureTransport": "false" } },
          ...overrides,
        },
      ],
    };
  }

  it("passes the canonical TLS-enforcing deny", () => {
    expect(statusOf("cek/tls-enforced", withPolicy(deny()))).toBe("pass");
  });

  const rejected: readonly [string, Record<string, unknown>][] = [
    [
      "the condition has the wrong sense",
      { Condition: { Bool: { "aws:SecureTransport": "true" } } },
    ],
    ["it is an Allow, not a Deny", { Effect: "Allow" }],
    ["it names one principal", { Principal: { AWS: "arn:aws:iam::123456789012:root" } }],
    ["it covers one action", { Action: "s3:GetObject" }],
    [
      "the operator is not Bool",
      { Condition: { StringEquals: { "aws:SecureTransport": "false" } } },
    ],
    // The deny must apply to *this* bucket's objects.
    ["it names a different bucket", { Resource: "arn:aws:s3:::other/*" }],
    ["it names one prefix of this bucket", { Resource: "arn:aws:s3:::b/only-this/*" }],
  ];
  for (const [name, overrides] of rejected) {
    it(`fails when ${name}`, () => {
      expect(statusOf("cek/tls-enforced", withPolicy(deny(overrides)))).toBe("fail");
    });
  }

  // An unreadable policy is not evidence that the bucket is unprotected.
  it("is not_applicable when the policy is not known until apply", () => {
    expect(statusOf("cek/tls-enforced", withPolicy(deny(), true))).toBe("not_applicable");
  });

  it("is not_applicable when the policy cannot be parsed", () => {
    expect(statusOf("cek/tls-enforced", withPolicy("{not json"))).toBe("not_applicable");
  });

  // The verdict is right in both cases, but the reason is audit evidence: a
  // malformed policy must not be described as "not known until apply".
  it("distinguishes an unreadable policy from one not yet known, in the reason", () => {
    const unreadable = run("cek/tls-enforced", withPolicy("{not json"))[0]?.reason ?? "";
    const notYetKnown = run("cek/tls-enforced", withPolicy(deny(), true))[0]?.reason ?? "";

    expect(unreadable).toContain("could not be read");
    expect(unreadable).not.toContain("not known until apply");
    expect(notYetKnown).toContain("not known until apply");
  });

  // A correct deny in GovCloud or China must not be reported as a failure.
  for (const partition of ["aws-us-gov", "aws-cn"]) {
    it(`passes a deny in the ${partition} partition`, () => {
      expect(
        statusOf("cek/tls-enforced", withPolicy(deny({ Resource: `arn:${partition}:s3:::b/*` }))),
      ).toBe("pass");
    });
  }

  it("passes the canonical two-ARN form", () => {
    expect(
      statusOf(
        "cek/tls-enforced",
        withPolicy(deny({ Resource: ["arn:aws:s3:::b", "arn:aws:s3:::b/*"] })),
      ),
    ).toBe("pass");
  });

  it("fails a deny naming only the bucket ARN, which does not cover objects", () => {
    expect(statusOf("cek/tls-enforced", withPolicy(deny({ Resource: "arn:aws:s3:::b" })))).toBe(
      "fail",
    );
  });

  it("fails an ARN naming a partition that does not exist", () => {
    expect(statusOf("cek/tls-enforced", withPolicy(deny({ Resource: "arn:awsX:s3:::b/*" })))).toBe(
      "fail",
    );
  });

  it("fails a deny using an inverted matcher, which cannot be evaluated", () => {
    expect(statusOf("cek/tls-enforced", withPolicy(deny({ NotAction: ["s3:DeleteBucket"] })))).toBe(
      "fail",
    );
  });

  it("fails a bucket with no policy at all", () => {
    expect(statusOf("cek/tls-enforced", model(bucket))).toBe("fail");
  });
});

describe("cek/encryption-at-rest", () => {
  const bucket = resource("aws_s3_bucket.b", "aws_s3_bucket", { bucket: "b" });

  function sseConfig(bucketName: unknown, unknown = false): Resource {
    return resource(
      "aws_s3_bucket_server_side_encryption_configuration.c",
      "aws_s3_bucket_server_side_encryption_configuration",
      { bucket: bucketName },
      unknown ? ["bucket"] : [],
    );
  }

  it("passes a bucket with a matching configuration", () => {
    expect(statusOf("cek/encryption-at-rest", model(bucket, sseConfig("b")))).toBe("pass");
  });

  it("fails a bucket with none", () => {
    expect(statusOf("cek/encryption-at-rest", model(bucket))).toBe("fail");
  });

  // `bucket = aws_s3_bucket.x.id` is unknown on a create plan, which is the
  // ordinary case, so this must not read as "no configuration exists".
  it("is not_applicable when a correlator's bucket is not known until apply", () => {
    expect(statusOf("cek/encryption-at-rest", model(bucket, sseConfig(null, true)))).toBe(
      "not_applicable",
    );
  });

  it("is not_applicable when an EBS volume's encrypted flag is unknown", () => {
    const volume = resource("aws_ebs_volume.v", "aws_ebs_volume", { encrypted: null }, [
      "encrypted",
    ]);
    expect(statusOf("cek/encryption-at-rest", model(volume))).toBe("not_applicable");
  });

  it("fails an unencrypted EBS volume", () => {
    const volume = resource("aws_ebs_volume.v", "aws_ebs_volume", { encrypted: false });
    expect(statusOf("cek/encryption-at-rest", model(volume))).toBe("fail");
  });

  // The absent/unknown split is the whole reason readAttribute exists: absent
  // means the operator did not ask for encryption, unknown means we cannot see.
  it("fails an absent encrypted flag but declines an unknown one", () => {
    const absent = resource("aws_ebs_volume.v", "aws_ebs_volume", {});
    const nulled = resource("aws_ebs_volume.v", "aws_ebs_volume", { encrypted: null });
    const unknown = resource("aws_ebs_volume.v", "aws_ebs_volume", { encrypted: null }, [
      "encrypted",
    ]);

    expect(statusOf("cek/encryption-at-rest", model(absent))).toBe("fail");
    expect(statusOf("cek/encryption-at-rest", model(nulled))).toBe("fail");
    expect(statusOf("cek/encryption-at-rest", model(unknown))).toBe("not_applicable");
  });
});

describe("cek/kms-key-rotation", () => {
  function key(
    attributes: Record<string, unknown>,
    unknown: readonly string[] = [],
  ): ResourceModel {
    return model(resource("aws_kms_key.k", "aws_kms_key", attributes, unknown));
  }

  it("passes a rotated symmetric key", () => {
    expect(statusOf("cek/kms-key-rotation", key({ enable_key_rotation: true }))).toBe("pass");
  });

  it("fails an unrotated symmetric key", () => {
    expect(statusOf("cek/kms-key-rotation", key({ enable_key_rotation: false }))).toBe("fail");
  });

  it("is not_applicable for an asymmetric key, which cannot rotate", () => {
    expect(
      statusOf(
        "cek/kms-key-rotation",
        key({ enable_key_rotation: false, customer_master_key_spec: "RSA_4096" }),
      ),
    ).toBe("not_applicable");
  });

  // Whether the control applies at all depends on the spec, so an unknown spec
  // must not be defaulted into "symmetric, therefore failing".
  it("is not_applicable when the key spec is not known until apply", () => {
    expect(
      statusOf(
        "cek/kms-key-rotation",
        key({ enable_key_rotation: false }, ["customer_master_key_spec"]),
      ),
    ).toBe("not_applicable");
  });
});
