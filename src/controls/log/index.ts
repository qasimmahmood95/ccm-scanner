import type { Check } from "../../engine/check.js";
import { resourcesOfType, type Resource, type ResourceModel } from "../../model/resource.js";
import { fail, notApplicable, pass, type Evidence, type Finding } from "../../model/verdict.js";
import { asText, readAttribute, unknownReason } from "../support/attributes.js";
import {
  correlateBy,
  correlatedFindings,
  coverageOf,
  S3_BUCKET,
  VPC,
  type Correlation,
} from "../support/correlate.js";
import { qualifiesAsFullBlock } from "../support/s3.js";

const TRAIL_TYPE = "aws_cloudtrail";

/**
 * A trail is account-scoped, and in practice lives in a dedicated audit or
 * organisation module rather than alongside the workloads it records. An input
 * that declares no trail is therefore not evidence that the account has none —
 * failing it would infer non-compliance we cannot support (hard constraint 5).
 *
 * The reason names what was looked for, so the gap stays visible rather than
 * being quietly reported as a Pass.
 */
function trailFindings(
  model: ResourceModel,
  control: string,
  evaluate: (trail: Resource) => Finding,
): readonly Finding[] {
  const trails = resourcesOfType(model, TRAIL_TYPE);
  if (trails.length === 0) {
    return [
      notApplicable(
        `No ${TRAIL_TYPE} is declared in this input, so ${control} cannot be evidenced from ` +
          `it. A trail is account-scoped and commonly managed in a separate audit module.`,
      ),
    ];
  }
  return trails.map(evaluate);
}

/** Reads a boolean trail attribute into evidence, or explains why it cannot. */
interface BooleanRequirement {
  readonly attribute: string;
  readonly expected: string;
}

function evaluateBooleans(trail: Resource, requirements: readonly BooleanRequirement[]): Finding {
  const evidence: Evidence[] = [];
  let unmet = 0;

  for (const requirement of requirements) {
    const read = readAttribute(trail, requirement.attribute);
    if (read.kind === "unknown") {
      return notApplicable(unknownReason(trail, requirement.attribute));
    }
    const value = read.kind === "value" ? read.value : null;
    if (value !== true) {
      unmet += 1;
    }
    evidence.push({
      resourceAddress: trail.address,
      attribute: requirement.attribute,
      observed: value,
      expected: requirement.expected,
    });
  }

  return unmet > 0 ? fail(evidence) : pass(evidence);
}

/**
 * LOG-07 — Logging Scope.
 *
 * A single-region trail records nothing about activity in every other region,
 * and a trail excluding global service events misses IAM and STS entirely —
 * both leave the audit log with holes an auditor would care about.
 */
const cloudtrailMultiRegion: Check = {
  checkId: "log/cloudtrail-multi-region",
  ccmId: "LOG-07",
  ccmTitle: "Logging Scope",
  run: (model) =>
    trailFindings(model, "logging scope", (trail) =>
      evaluateBooleans(trail, [
        { attribute: "is_multi_region_trail", expected: "true" },
        { attribute: "include_global_service_events", expected: "true" },
      ]),
    ),
};

/** The bucket a trail delivers to, or undefined when it cannot be resolved. */
function logBucketName(trail: Resource): string | undefined {
  return asText(readAttribute(trail, "s3_bucket_name"));
}

/**
 * Combines the trail-side verdict with the bucket-side one.
 *
 * The bucket half is only evidenceable when the log bucket is declared in this
 * same input. When it is not, we still report the trail-side finding rather
 * than discarding it — but the reason must say the bucket was not examined, or
 * a Pass would claim more than we checked.
 */
function withLogBucket(
  model: ResourceModel,
  trail: Resource,
  correlation: Correlation,
  expected: string,
  trailSide: Finding,
): Finding {
  // The trail half is decisive when it fails — an unvalidated log is
  // unprotected whatever the bucket does — and when it could not be read at
  // all. Only a passing trail hands the verdict to the bucket.
  if (trailSide.status !== "pass") {
    return trailSide;
  }

  const read = readAttribute(trail, "s3_bucket_name");
  if (read.kind === "unknown") {
    return notApplicable(unknownReason(trail, "s3_bucket_name"));
  }
  const name = asText(read);
  if (name === undefined) {
    return notApplicable(
      `${trail.address} names no s3_bucket_name, so its log bucket cannot be identified.`,
    );
  }

  const coverage = coverageOf(model, S3_BUCKET, correlation, name);
  switch (coverage.kind) {
    case "covered":
      return trailSide;
    case "uncovered":
      return fail([
        {
          resourceAddress: trail.address,
          attribute: "s3_bucket_name",
          observed: `log bucket "${name}" is declared but does not satisfy: ${expected}`,
          expected,
        },
      ]);
    // Half-checked is not checked. Reporting the trail's own Pass here would
    // claim the logs are protected when we never looked at where they land.
    case "undeclared":
      return notApplicable(
        `${trail.address} satisfies its own half of this control, but delivers to ` +
          `"${name}", which this input does not declare — so whether the bucket holding ` +
          `the logs is protected cannot be evidenced here.`,
      );
    case "unresolvable":
      return notApplicable(
        `${trail.address} satisfies its own half of this control, but the protection of ` +
          `"${name}" cannot be correlated: ${coverage.detail}.`,
      );
  }
}

/**
 * LOG-02 — Audit Logs Protection.
 *
 * Two halves: the trail validates its own log files, and the bucket holding
 * them is encrypted and not public. A tamper-evident log in a world-readable
 * bucket is not a protected log.
 */
const cloudtrailLogValidation: Check = {
  checkId: "log/cloudtrail-log-validation",
  ccmId: "LOG-02",
  ccmTitle: "Audit Logs Protection",
  run: (model) => {
    // A log bucket qualifies only if it is *both* encrypted and fully blocked;
    // either alone leaves the audit trail exposed.
    const encrypted = correlateBy(
      model,
      "aws_s3_bucket_server_side_encryption_configuration",
      "bucket",
      () => ({ kind: "yes" }),
    );
    const blocked = correlateBy(model, "aws_s3_bucket_public_access_block", "bucket", (block) =>
      qualifiesAsFullBlock(block),
    );
    const protectedBuckets: Correlation = {
      keys: new Set([...encrypted.keys].filter((name) => blocked.keys.has(name))),
      unresolvable: [...encrypted.unresolvable, ...blocked.unresolvable],
    };

    return trailFindings(model, "audit log protection", (trail) => {
      const trailSide = evaluateBooleans(trail, [
        { attribute: "enable_log_file_validation", expected: "true" },
      ]);
      return withLogBucket(
        model,
        trail,
        protectedBuckets,
        "the log bucket to be both server-side encrypted and fully public-access-blocked",
        trailSide,
      );
    });
  },
};

/**
 * LOG-04 — Audit Logs Access and Accountability.
 *
 * Either signal satisfies the control: delivery to CloudWatch Logs gives an
 * independent copy with its own access control, and server access logging on
 * the log bucket records who read the trail. Partial coverage by design —
 * neither evidences who *actually* accessed the logs, only that access is
 * accountable.
 */
const cloudtrailAccountability: Check = {
  checkId: "log/cloudtrail-accountability",
  ccmId: "LOG-04",
  ccmTitle: "Audit Logs Access and Accountability",
  run: (model) => {
    const accessLogged = correlateBy(model, "aws_s3_bucket_logging", "bucket", () => ({
      kind: "yes",
    }));

    return trailFindings(model, "audit log accountability", (trail) => {
      const read = readAttribute(trail, "cloud_watch_logs_group_arn");
      if (read.kind === "unknown") {
        return notApplicable(unknownReason(trail, "cloud_watch_logs_group_arn"));
      }
      const group = asText(read);
      if (group !== undefined) {
        return pass([
          {
            resourceAddress: trail.address,
            attribute: "cloud_watch_logs_group_arn",
            observed: group,
            expected: "delivery to CloudWatch Logs, or access logging on the log bucket",
          },
        ]);
      }

      // No CloudWatch delivery, so the bucket's access logging is the only
      // remaining signal.
      const name = logBucketName(trail);
      if (readAttribute(trail, "s3_bucket_name").kind === "unknown") {
        return notApplicable(unknownReason(trail, "s3_bucket_name"));
      }
      if (name === undefined) {
        return notApplicable(
          `${trail.address} has no CloudWatch Logs group and names no s3_bucket_name, so ` +
            `neither accountability signal can be evidenced.`,
        );
      }

      const coverage = coverageOf(model, S3_BUCKET, accessLogged, name);
      const evidence: Evidence[] = [
        {
          resourceAddress: trail.address,
          attribute: "cloud_watch_logs_group_arn",
          observed: null,
          expected: "delivery to CloudWatch Logs, or access logging on the log bucket",
        },
      ];
      switch (coverage.kind) {
        case "covered":
          return pass([
            {
              resourceAddress: trail.address,
              attribute: "s3_bucket_name",
              observed: `log bucket "${name}" has server access logging`,
              expected: "delivery to CloudWatch Logs, or access logging on the log bucket",
            },
          ]);
        case "uncovered":
          return fail(evidence);
        case "undeclared":
          return notApplicable(
            `${trail.address} has no CloudWatch Logs group, and its log bucket "${name}" is ` +
              `not declared in this input, so whether access to the logs is accountable ` +
              `cannot be evidenced here.`,
          );
        case "unresolvable":
          return notApplicable(
            `Access logging for "${name}" cannot be correlated: ${coverage.detail}.`,
          );
      }
    });
  },
};

/**
 * LOG-03 — Security Monitoring and Alerting.
 *
 * Flow logs are the monitoring signal a VPC can actually carry in
 * infrastructure-as-code. Whether anyone reads them, and whether alarms are
 * tuned, is runtime behaviour this input cannot show — hence partial coverage,
 * stated rather than implied.
 *
 * A create plan reports `aws_vpc.id` as unknown, so this control usually only
 * resolves against applied state. That is honest: the correlation genuinely
 * cannot be made from a plan.
 */
const vpcFlowLogs: Check = {
  checkId: "log/vpc-flow-logs",
  ccmId: "LOG-03",
  ccmTitle: "Security Monitoring and Alerting",
  run: (model) => {
    if (resourcesOfType(model, VPC.type).length === 0) {
      return [notApplicable("This input declares no VPCs, so flow-log coverage does not apply.")];
    }
    return correlatedFindings(
      model,
      VPC,
      correlateBy(model, "aws_flow_log", "vpc_id", () => ({ kind: "yes" })),
      (covered, id) => ({
        attribute: "id",
        observed: covered ? "an aws_flow_log targets this VPC" : `no aws_flow_log targets "${id}"`,
        expected: "a VPC flow log capturing this VPC's traffic",
      }),
    );
  },
};

/** LOG-05 — Audit Logs Monitoring and Response. An operational activity. */
const monitoringAndResponse: Check = {
  checkId: "log/na-operational",
  ccmId: "LOG-05",
  ccmTitle: "Audit Logs Monitoring and Response",
  run: () => [
    notApplicable(
      "Monitoring logs and responding to what they show is an operational activity. " +
        "Declarative infrastructure can show that a log exists, never that anyone acted on it.",
    ),
  ],
};

/** LOG-06 — Clock Synchronization. Host/runtime configuration. */
const clockSynchronization: Check = {
  checkId: "log/na-host-runtime",
  ccmId: "LOG-06",
  ccmTitle: "Clock Synchronization",
  run: () => [
    notApplicable(
      "NTP and clock synchronisation are configured inside the host or image, below the " +
        "infrastructure graph this scanner reads.",
    ),
  ],
};

export const logChecks: readonly Check[] = [
  cloudtrailLogValidation,
  vpcFlowLogs,
  cloudtrailAccountability,
  monitoringAndResponse,
  clockSynchronization,
  cloudtrailMultiRegion,
];
