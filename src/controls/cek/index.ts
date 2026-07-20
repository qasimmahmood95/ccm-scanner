import type { Check } from "../../engine/check.js";
import { resourcesOfType, type Resource, type ResourceModel } from "../../model/resource.js";
import { fail, notApplicable, pass, type Evidence, type Finding } from "../../model/verdict.js";
import { asText, readAttribute, unknownReason } from "../support/attributes.js";
import {
  isWildcardPrincipal,
  parsePolicyDocument,
  usesInvertedMatch,
  type PolicyStatement,
} from "../support/iam-policy.js";

/** Resource types whose encryption-at-rest is a single boolean attribute. */
const BOOLEAN_ENCRYPTION: readonly { readonly type: string; readonly attribute: string }[] = [
  { type: "aws_ebs_volume", attribute: "encrypted" },
  { type: "aws_db_instance", attribute: "storage_encrypted" },
  { type: "aws_rds_cluster", attribute: "storage_encrypted" },
];

/**
 * ELB policies that permit only TLS 1.2 or better.
 *
 * This is an allowlist, deliberately. A denylist asserts that everything it has
 * not heard of is compliant, which for a policy family AWS keeps extending
 * means new weak selections would silently pass. An unrecognised policy is
 * reported not-applicable, naming it, rather than approved.
 */
const APPROVED_TLS_POLICIES = new Set([
  "ELBSecurityPolicy-TLS13-1-2-2021-06",
  "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
  "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
  "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
  "ELBSecurityPolicy-TLS13-1-3-2021-06",
  "ELBSecurityPolicy-TLS-1-2-2017-01",
  "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
  "ELBSecurityPolicy-FS-1-2-2019-08",
  "ELBSecurityPolicy-FS-1-2-Res-2019-08",
  "ELBSecurityPolicy-FS-1-2-Res-2020-10",
]);

/** Policies known to permit TLS 1.0 or 1.1 — an evidenced failure, not a shrug. */
const KNOWN_WEAK_TLS_POLICIES = new Set([
  "ELBSecurityPolicy-2015-05",
  "ELBSecurityPolicy-2016-08",
  "ELBSecurityPolicy-TLS-1-0-2015-04",
  "ELBSecurityPolicy-TLS-1-1-2017-01",
  "ELBSecurityPolicy-FS-2018-06",
  "ELBSecurityPolicy-FS-1-1-2019-08",
  "ELBSecurityPolicy-TLS13-1-0-2021-06",
  "ELBSecurityPolicy-TLS13-1-1-2021-06",
]);

const APPROVED_SSE_ALGORITHMS = new Set(["aws:kms", "aws:kms:dsse", "AES256"]);

const SSE_CONFIG_TYPE = "aws_s3_bucket_server_side_encryption_configuration";

/**
 * A correlation over bucket *names*, which is how S3's satellite resources
 * point at their bucket.
 *
 * The name is routinely `aws_s3_bucket.x.id`, which a create plan reports as
 * unknown until apply. Treating that as "no configuration targets this bucket"
 * would fail a bucket that is in fact encrypted, so unresolvable correlators
 * are tracked and make the answer not-applicable rather than a Fail.
 */
interface Correlation {
  readonly names: ReadonlySet<string>;
  readonly unresolvable: readonly string[];
}

/**
 * Whether a satellite resource satisfies the control for its bucket.
 * `unresolvable` is distinct from `no`: it means the input cannot tell us,
 * which must become not-applicable rather than a failure.
 */
type Qualification =
  | { readonly kind: "yes" }
  | { readonly kind: "no" }
  | { readonly kind: "unresolvable"; readonly attribute: string };

function correlateByBucket(
  model: ResourceModel,
  type: string,
  qualifies: (resource: Resource, bucketName: string) => Qualification,
): Correlation {
  const names = new Set<string>();
  const unresolvable: string[] = [];

  for (const resource of resourcesOfType(model, type)) {
    const read = readAttribute(resource, "bucket");
    const bucket = read.kind === "unknown" ? undefined : asText(read);
    if (bucket === undefined) {
      unresolvable.push(`${resource.address}.bucket`);
      continue;
    }
    const qualification = qualifies(resource, bucket);
    if (qualification.kind === "yes") {
      names.add(bucket);
    } else if (qualification.kind === "unresolvable") {
      unresolvable.push(`${resource.address}.${qualification.attribute}`);
    }
  }
  return { names, unresolvable };
}

/** Resolves each bucket to its name, or explains why it cannot be correlated. */
function bucketFindings(
  model: ResourceModel,
  correlation: Correlation,
  describe: (covered: boolean, name: string) => Omit<Evidence, "resourceAddress">,
): readonly Finding[] {
  return resourcesOfType(model, "aws_s3_bucket").map((bucket): Finding => {
    const read = readAttribute(bucket, "bucket");
    if (read.kind === "unknown") {
      return notApplicable(unknownReason(bucket, "bucket"));
    }
    const name = asText(read);
    if (name === undefined) {
      return notApplicable(
        `${bucket.address} has no resolvable bucket name, so its configuration cannot be correlated.`,
      );
    }
    const covered = correlation.names.has(name);
    if (!covered && correlation.unresolvable.length > 0) {
      return notApplicable(
        `${bucket.address} cannot be correlated: ${correlation.unresolvable.join(", ")} ` +
          `${correlation.unresolvable.length === 1 ? "is" : "are"} not known until apply, so a ` +
          `configuration targeting this bucket may exist without being visible here.`,
      );
    }
    const evidence: Evidence = { resourceAddress: bucket.address, ...describe(covered, name) };
    return covered ? pass([evidence]) : fail([evidence]);
  });
}

/** Every `sse_algorithm` declared by an SSE configuration resource. */
function sseAlgorithms(config: Resource): readonly string[] {
  const read = readAttribute(config, "rule");
  if (read.kind !== "value") {
    return [];
  }
  const rules = Array.isArray(read.value) ? read.value : [read.value];
  const algorithms: string[] = [];
  for (const entry of rules) {
    if (typeof entry !== "object" || entry === null) {
      continue;
    }
    const applied = (entry as Record<string, unknown>).apply_server_side_encryption_by_default;
    for (const item of Array.isArray(applied) ? applied : [applied]) {
      if (typeof item !== "object" || item === null) {
        continue;
      }
      const algorithm = (item as Record<string, unknown>).sse_algorithm;
      if (typeof algorithm === "string" && algorithm !== "") {
        algorithms.push(algorithm);
      }
    }
  }
  return algorithms;
}

/** CEK-03 — Data Encryption (at rest). */
const encryptionAtRest: Check = {
  checkId: "cek/encryption-at-rest",
  ccmId: "CEK-03",
  ccmTitle: "Data Encryption",
  run: (model) => {
    const findings: Finding[] = [
      ...bucketFindings(
        model,
        correlateByBucket(model, SSE_CONFIG_TYPE, () => ({ kind: "yes" })),
        (covered, name) => ({
          attribute: "bucket",
          observed: covered
            ? `covered by an ${SSE_CONFIG_TYPE}`
            : `no ${SSE_CONFIG_TYPE} targets "${name}"`,
          expected: "server-side encryption configured for the bucket",
        }),
      ),
    ];

    for (const { type, attribute } of BOOLEAN_ENCRYPTION) {
      for (const resource of resourcesOfType(model, type)) {
        const read = readAttribute(resource, attribute);
        if (read.kind === "unknown") {
          findings.push(notApplicable(unknownReason(resource, attribute)));
          continue;
        }
        const evidence: Evidence[] = [
          {
            resourceAddress: resource.address,
            attribute,
            observed: read.kind === "value" ? read.value : null,
            expected: "true",
          },
        ];
        findings.push(
          read.kind === "value" && read.value === true ? pass(evidence) : fail(evidence),
        );
      }
    }

    if (findings.length === 0) {
      return [
        notApplicable(
          "This input declares no storage whose encryption at rest is visible in Terraform.",
        ),
      ];
    }
    return findings;
  },
};

/**
 * A statement that genuinely forces TLS: deny everyone, on the bucket's
 * objects, when the request did not arrive over TLS. Matching only the
 * condition *key* would also accept `SecureTransport: true` — a policy that
 * denies encrypted traffic and enforces nothing.
 */
export function deniesInsecureTransport(statement: PolicyStatement, bucketName: string): boolean {
  if (statement.effect !== "Deny" || usesInvertedMatch(statement)) {
    return false;
  }
  const enforcing = statement.conditions.some(
    (condition) =>
      condition.key === "aws:securetransport" &&
      (condition.operator === "bool" || condition.operator === "boolifexists") &&
      condition.values.includes("false"),
  );
  if (!enforcing || !statement.principals.some(isWildcardPrincipal)) {
    return false;
  }
  if (!statement.actions.some((action) => action === "*" || action.toLowerCase() === "s3:*")) {
    return false;
  }
  // A deny scoped to some other bucket, or to one prefix of this one, does not
  // enforce TLS for this bucket's objects — and claiming it does would be a
  // Pass on an assertion we never made.
  return statement.resources.some(
    (resource) => resource === "*" || resource === `arn:aws:s3:::${bucketName}/*`,
  );
}

/** CEK-03 — Data Encryption (in transit). */
const tlsEnforced: Check = {
  checkId: "cek/tls-enforced",
  ccmId: "CEK-03",
  ccmTitle: "Data Encryption",
  run: (model) => {
    if (resourcesOfType(model, "aws_s3_bucket").length === 0) {
      return [notApplicable("This input declares no S3 buckets.")];
    }

    const correlation = correlateByBucket(model, "aws_s3_bucket_policy", (policy, bucketName) => {
      const read = readAttribute(policy, "policy");
      // An unreadable document is not evidence that the bucket is unprotected.
      if (read.kind === "unknown") {
        return { kind: "unresolvable", attribute: "policy" };
      }
      if (read.kind === "absent") {
        return { kind: "no" };
      }
      const parsed = parsePolicyDocument(read.value);
      if (parsed.kind === "unparseable") {
        return { kind: "unresolvable", attribute: "policy" };
      }
      if (parsed.kind === "empty") {
        return { kind: "no" };
      }
      return parsed.statements.some((statement) => deniesInsecureTransport(statement, bucketName))
        ? { kind: "yes" }
        : { kind: "no" };
    });

    return bucketFindings(model, correlation, (covered, name) => ({
      attribute: "bucket",
      observed: covered
        ? "a bucket policy denies all non-TLS requests"
        : `no aws_s3_bucket_policy denies non-TLS access to "${name}"`,
      expected: "a policy denying every principal when aws:SecureTransport is false",
    }));
  },
};

/** CEK-04 — Encryption Algorithm. */
const approvedAlgorithms: Check = {
  checkId: "cek/approved-algorithms",
  ccmId: "CEK-04",
  ccmTitle: "Encryption Algorithm",
  run: (model) => {
    const findings: Finding[] = [];

    for (const config of resourcesOfType(model, SSE_CONFIG_TYPE)) {
      const read = readAttribute(config, "rule");
      if (read.kind === "unknown") {
        findings.push(notApplicable(unknownReason(config, "rule")));
        continue;
      }
      const algorithms = sseAlgorithms(config);
      if (algorithms.length === 0) {
        findings.push(
          notApplicable(`${config.address} declares no resolvable server-side encryption rule.`),
        );
        continue;
      }
      const disallowed = algorithms.filter((algorithm) => !APPROVED_SSE_ALGORITHMS.has(algorithm));
      const evidence: Evidence[] = [
        {
          resourceAddress: config.address,
          attribute: "rule[].apply_server_side_encryption_by_default.sse_algorithm",
          observed: algorithms,
          expected: `one of ${[...APPROVED_SSE_ALGORITHMS].join(", ")}`,
        },
      ];
      findings.push(disallowed.length > 0 ? fail(evidence) : pass(evidence));
    }

    for (const listener of resourcesOfType(model, "aws_lb_listener")) {
      const read = readAttribute(listener, "ssl_policy");
      if (read.kind === "unknown") {
        findings.push(notApplicable(unknownReason(listener, "ssl_policy")));
        continue;
      }
      const policy = asText(read);
      if (policy === undefined) {
        // No TLS policy means a plaintext listener: a network-exposure question
        // (IVS), not an algorithm one.
        continue;
      }
      const evidence: Evidence[] = [
        {
          resourceAddress: listener.address,
          attribute: "ssl_policy",
          observed: policy,
          expected: "a TLS policy permitting only TLS 1.2 or better",
        },
      ];
      if (APPROVED_TLS_POLICIES.has(policy)) {
        findings.push(pass(evidence));
      } else if (KNOWN_WEAK_TLS_POLICIES.has(policy)) {
        findings.push(fail(evidence));
      } else {
        findings.push(
          notApplicable(
            `${listener.address} uses TLS policy "${policy}", which is not on the approved ` +
              `or known-weak list, so the algorithms it permits cannot be evidenced here.`,
          ),
        );
      }
    }

    if (findings.length === 0) {
      return [
        notApplicable(
          "This input declares no encryption algorithm or TLS policy selections to inspect.",
        ),
      ];
    }
    return findings;
  },
};

/** CEK-12 — Key Rotation. Only symmetric customer-managed keys support rotation. */
const kmsKeyRotation: Check = {
  checkId: "cek/kms-key-rotation",
  ccmId: "CEK-12",
  ccmTitle: "Key Rotation",
  run: (model) => {
    const keys = resourcesOfType(model, "aws_kms_key");
    if (keys.length === 0) {
      return [notApplicable("This input declares no customer-managed KMS keys.")];
    }

    return keys.map((key): Finding => {
      // Whether the control applies at all depends on the key spec, so an
      // unknown spec must not be defaulted into "symmetric, therefore in scope".
      const specRead = readAttribute(key, "customer_master_key_spec");
      if (specRead.kind === "unknown") {
        return notApplicable(unknownReason(key, "customer_master_key_spec"));
      }
      const spec = asText(specRead) ?? "SYMMETRIC_DEFAULT";
      if (spec !== "SYMMETRIC_DEFAULT") {
        return notApplicable(
          `${key.address} is ${spec}; AWS does not support automatic rotation for ` +
            `asymmetric keys, so the control does not apply.`,
        );
      }

      const read = readAttribute(key, "enable_key_rotation");
      if (read.kind === "unknown") {
        return notApplicable(unknownReason(key, "enable_key_rotation"));
      }

      const evidence: Evidence[] = [
        {
          resourceAddress: key.address,
          attribute: "enable_key_rotation",
          observed: read.kind === "value" ? read.value : null,
          expected: "true",
        },
      ];
      return read.kind === "value" && read.value === true ? pass(evidence) : fail(evidence);
    });
  },
};

/** CEK-01 — Encryption and Key Management Policy and Procedures. Governance, not infrastructure. */
const encryptionGovernance: Check = {
  checkId: "cek/na-governance",
  ccmId: "CEK-01",
  ccmTitle: "Encryption and Key Management Policy and Procedures",
  run: () => [
    notApplicable(
      "A policy-and-procedures document is a governance artifact. Declarative " +
        "infrastructure carries no signal of whether one exists or is followed.",
    ),
  ],
};

/** CEK-14 — Key Destruction. A runtime lifecycle operation. */
const keyDestruction: Check = {
  checkId: "cek/na-lifecycle-runtime",
  ccmId: "CEK-14",
  ccmTitle: "Key Destruction",
  run: () => [
    notApplicable(
      "Key destruction is a runtime lifecycle operation. deletion_window_in_days states " +
        "intent but does not evidence that a key was ever destroyed.",
    ),
  ],
};

export const cekChecks: readonly Check[] = [
  encryptionGovernance,
  encryptionAtRest,
  tlsEnforced,
  approvedAlgorithms,
  kmsKeyRotation,
  keyDestruction,
];
