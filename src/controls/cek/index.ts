import type { Check } from "../../engine/check.js";
import { resourcesOfType, type ResourceModel } from "../../model/resource.js";
import { fail, notApplicable, pass, type Evidence, type Finding } from "../../model/verdict.js";
import { asText, readAttribute, unknownReason } from "../support/attributes.js";
import { parsePolicyDocument } from "../support/iam-policy.js";

/** Resource types whose encryption-at-rest is a single boolean attribute. */
const BOOLEAN_ENCRYPTION: readonly { readonly type: string; readonly attribute: string }[] = [
  { type: "aws_ebs_volume", attribute: "encrypted" },
  { type: "aws_db_instance", attribute: "storage_encrypted" },
  { type: "aws_rds_cluster", attribute: "storage_encrypted" },
];

/** TLS policies that still permit TLS 1.0/1.1. */
const WEAK_TLS_POLICIES = new Set([
  "ELBSecurityPolicy-2016-08",
  "ELBSecurityPolicy-TLS-1-0-2015-04",
  "ELBSecurityPolicy-TLS-1-1-2017-01",
  "ELBSecurityPolicy-FS-2018-06",
]);

const APPROVED_SSE_ALGORITHMS = new Set(["aws:kms", "aws:kms:dsse", "AES256"]);

/** Bucket names that some `aws_s3_bucket_server_side_encryption_configuration` covers. */
function encryptedBucketNames(model: ResourceModel): ReadonlySet<string> {
  const names = new Set<string>();
  for (const config of resourcesOfType(
    model,
    "aws_s3_bucket_server_side_encryption_configuration",
  )) {
    const bucket = asText(readAttribute(config, "bucket"));
    if (bucket !== undefined) {
      names.add(bucket);
    }
  }
  return names;
}

/**
 * CEK-03 — Data Encryption (at rest).
 *
 * Covers the storage types whose encryption is visible in Terraform. S3 keeps
 * its encryption in a separate resource, so buckets are correlated by name.
 */
const encryptionAtRest: Check = {
  checkId: "cek/encryption-at-rest",
  ccmId: "CEK-03",
  ccmTitle: "Data Encryption",
  run: (model) => {
    const findings: Finding[] = [];
    const encryptedBuckets = encryptedBucketNames(model);

    for (const bucket of resourcesOfType(model, "aws_s3_bucket")) {
      const read = readAttribute(bucket, "bucket");
      if (read.kind === "unknown") {
        findings.push(notApplicable(unknownReason(bucket, "bucket")));
        continue;
      }
      const name = asText(read);
      if (name === undefined) {
        findings.push(
          notApplicable(
            `${bucket.address} has no resolvable bucket name, so its encryption ` +
              `configuration cannot be correlated.`,
          ),
        );
        continue;
      }
      const covered = encryptedBuckets.has(name);
      const evidence: Evidence[] = [
        {
          resourceAddress: bucket.address,
          attribute: "bucket",
          observed: covered
            ? `covered by an aws_s3_bucket_server_side_encryption_configuration`
            : `no aws_s3_bucket_server_side_encryption_configuration targets "${name}"`,
          expected: "server-side encryption configured for the bucket",
        },
      ];
      findings.push(covered ? pass(evidence) : fail(evidence));
    }

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
 * CEK-03 — Data Encryption (in transit).
 *
 * A bucket is compliant when its policy denies requests made without TLS.
 */
const tlsEnforced: Check = {
  checkId: "cek/tls-enforced",
  ccmId: "CEK-03",
  ccmTitle: "Data Encryption",
  run: (model) => {
    const buckets = resourcesOfType(model, "aws_s3_bucket");
    if (buckets.length === 0) {
      return [notApplicable("This input declares no S3 buckets.")];
    }

    const denyingBuckets = new Set<string>();
    for (const policy of resourcesOfType(model, "aws_s3_bucket_policy")) {
      const bucket = asText(readAttribute(policy, "bucket"));
      const document = readAttribute(policy, "policy");
      const statements =
        document.kind === "value" ? parsePolicyDocument(document.value) : undefined;
      if (bucket === undefined || statements === undefined) {
        continue;
      }
      const denies = statements.some(
        (statement) =>
          statement.effect === "Deny" && statement.conditionKeys.includes("aws:securetransport"),
      );
      if (denies) {
        denyingBuckets.add(bucket);
      }
    }

    return buckets.map((bucket): Finding => {
      const read = readAttribute(bucket, "bucket");
      if (read.kind === "unknown") {
        return notApplicable(unknownReason(bucket, "bucket"));
      }
      const name = asText(read);
      if (name === undefined) {
        return notApplicable(
          `${bucket.address} has no resolvable bucket name, so its policy cannot be correlated.`,
        );
      }
      const denies = denyingBuckets.has(name);
      const evidence: Evidence[] = [
        {
          resourceAddress: bucket.address,
          attribute: "bucket",
          observed: denies
            ? "bucket policy denies requests where aws:SecureTransport is false"
            : `no aws_s3_bucket_policy denies non-TLS access to "${name}"`,
          expected: "a policy denying requests made without TLS",
        },
      ];
      return denies ? pass(evidence) : fail(evidence);
    });
  },
};

/** CEK-04 — Encryption Algorithm. SSE algorithms and TLS policies against an allowlist. */
const approvedAlgorithms: Check = {
  checkId: "cek/approved-algorithms",
  ccmId: "CEK-04",
  ccmTitle: "Encryption Algorithm",
  run: (model) => {
    const findings: Finding[] = [];

    for (const config of resourcesOfType(
      model,
      "aws_s3_bucket_server_side_encryption_configuration",
    )) {
      const read = readAttribute(config, "rule");
      if (read.kind === "unknown") {
        findings.push(notApplicable(unknownReason(config, "rule")));
        continue;
      }
      const algorithms = collectSseAlgorithms(read.kind === "value" ? read.value : undefined);
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
        // A listener without a TLS policy is a plaintext listener; that is a
        // network-exposure question (IVS), not an algorithm one.
        continue;
      }
      const evidence: Evidence[] = [
        {
          resourceAddress: listener.address,
          attribute: "ssl_policy",
          observed: policy,
          expected: "a TLS policy that does not permit TLS 1.0 or 1.1",
        },
      ];
      findings.push(WEAK_TLS_POLICIES.has(policy) ? fail(evidence) : pass(evidence));
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

/** Pulls every `sse_algorithm` out of an `aws_s3_bucket_server_side_encryption_configuration.rule`. */
function collectSseAlgorithms(rule: unknown): readonly string[] {
  const rules = Array.isArray(rule) ? rule : [rule];
  const algorithms: string[] = [];
  for (const entry of rules) {
    if (typeof entry !== "object" || entry === null) {
      continue;
    }
    const applied = (entry as Record<string, unknown>).apply_server_side_encryption_by_default;
    const applies = Array.isArray(applied) ? applied : [applied];
    for (const item of applies) {
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
      const spec = asText(readAttribute(key, "customer_master_key_spec")) ?? "SYMMETRIC_DEFAULT";
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
