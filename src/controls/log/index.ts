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
  const unknown: string[] = [];
  let unmet = 0;

  for (const requirement of requirements) {
    const read = readAttribute(trail, requirement.attribute);
    if (read.kind === "unknown") {
      unknown.push(requirement.attribute);
      continue;
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

  // Evidence of non-compliance is still evidence when a *different* attribute
  // is unknown: a single-region trail is single-region whatever the global
  // service events flag turns out to be. Returning not-applicable here would
  // discard a finding we can support (hard constraint 5 defines Fail as having
  // evidence of non-compliance, and we have it).
  if (unmet > 0) {
    return fail(evidence);
  }
  if (unknown.length > 0) {
    return notApplicable(
      `${unknown.map((attribute) => `${trail.address}.${attribute}`).join(", ")} ` +
        `${unknown.length === 1 ? "is" : "are"} not known until apply. Nothing else read from ` +
        `this trail is non-compliant, so the verdict cannot be settled from this input.`,
    );
  }
  return pass(evidence);
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
    // Both halves were checked, so the evidence must show both — a Pass citing
    // only the trail would not tell an auditor the bucket was examined at all.
    //
    // Each resource is described by what it actually is. A satellite does not
    // "hold the logs" — the bucket does — and no single satellite evidences the
    // whole requirement, so every one that contributed is cited rather than
    // collapsing them into one address making a claim none of them supports.
    case "covered":
      return pass([
        ...trailSide.evidence,
        ...(coverage.declared
          ? [
              {
                resourceAddress: coverage.address,
                attribute: "bucket",
                observed: `holds the logs of ${trail.address}`,
                expected,
              },
            ]
          : []),
        ...coverage.satellites.map((address) => ({
          resourceAddress: address,
          attribute: "bucket",
          observed: `configures log bucket "${name}"`,
          expected,
        })),
      ]);
    case "uncovered":
      return fail([
        ...trailSide.evidence,
        {
          resourceAddress: coverage.address,
          attribute: "bucket",
          observed: `holds the logs of ${trail.address} but does not satisfy: ${expected}`,
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
    // The intersection keeps *both* halves' satellites, so the evidence can
    // cite the resource that encrypts and the resource that blocks. Keeping
    // only one would leave a Pass asserting a requirement half its evidence
    // does not support.
    const protectedBuckets: Correlation = {
      keys: new Map(
        [...encrypted.keys].flatMap(([name, addresses]) => {
          const blocking = blocked.keys.get(name);
          return blocking === undefined ? [] : [[name, [...addresses, ...blocking]] as const];
        }),
      ),
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

    const EXPECTED = "delivery to CloudWatch Logs, or access logging on the log bucket";

    return trailFindings(model, "audit log accountability", (trail) => {
      const read = readAttribute(trail, "cloud_watch_logs_group_arn");
      const group = read.kind === "unknown" ? undefined : asText(read);
      if (group !== undefined) {
        return pass([
          {
            resourceAddress: trail.address,
            attribute: "cloud_watch_logs_group_arn",
            observed: group,
            expected: EXPECTED,
          },
        ]);
      }

      // Either signal satisfies this control, so an unknown CloudWatch group —
      // the ordinary shape when the ARN references a log group created in the
      // same plan — must not stop us looking at the bucket. Access logging on
      // its own is sufficient. What an unknown group does forbid is a *Fail*,
      // since the group may well be set once applied.
      //
      // Three ways to have no usable ARN, and they are not the same thing. An
      // empty string is Terraform's idiom for "unset" and is as definite as an
      // absent attribute, so it must still be able to Fail; only a value we
      // genuinely cannot interpret blocks that.
      const unreadableGroup = read.kind === "value" && typeof read.value !== "string";
      const groupUnsettled = read.kind === "unknown" || unreadableGroup;

      const bucketRead = readAttribute(trail, "s3_bucket_name");
      if (bucketRead.kind === "unknown") {
        return notApplicable(unknownReason(trail, "s3_bucket_name"));
      }
      // The branches below describe the CloudWatch side, so they must
      // distinguish "not set" from "not yet known" — asserting absence of a
      // value the plan simply has not computed is the same conflation this
      // check was fixed to remove.
      const cloudWatch =
        read.kind === "unknown"
          ? "has a CloudWatch Logs group that is not known until apply"
          : unreadableGroup
            ? "declares a cloud_watch_logs_group_arn that could not be read"
            : "has no CloudWatch Logs group";

      const name = asText(bucketRead);
      if (name === undefined) {
        return notApplicable(
          `${trail.address} ${cloudWatch} and names no s3_bucket_name, so neither ` +
            `accountability signal can be evidenced.`,
        );
      }

      const coverage = coverageOf(model, S3_BUCKET, accessLogged, name);
      switch (coverage.kind) {
        // The trail is named first, as LOG-02 does. Citing only the bucket's
        // satellite makes two trails sharing one log bucket produce
        // byte-identical verdicts, and hides that the CloudWatch half was
        // examined and found empty.
        case "covered":
          return pass([
            {
              resourceAddress: trail.address,
              attribute: "cloud_watch_logs_group_arn",
              observed: read.kind === "unknown" ? "not known until apply" : null,
              expected: EXPECTED,
            },
            ...coverage.satellites.map((address) => ({
              resourceAddress: address,
              attribute: "bucket",
              observed: `configures server access logging on log bucket "${name}"`,
              expected: EXPECTED,
            })),
          ]);
        case "uncovered":
          return groupUnsettled
            ? notApplicable(
                `${trail.address} ${cloudWatch} and its log bucket "${name}" has no server ` +
                  `access logging, so neither signal can be settled from this input.`,
              )
            : fail([
                {
                  resourceAddress: trail.address,
                  attribute: "cloud_watch_logs_group_arn",
                  observed: null,
                  expected: EXPECTED,
                },
                {
                  resourceAddress: coverage.address,
                  attribute: "bucket",
                  observed: `holds the logs of ${trail.address} but has no server access logging`,
                  expected: EXPECTED,
                },
              ]);
        case "undeclared":
          return notApplicable(
            `${trail.address} ${cloudWatch}, and its log bucket "${name}" is not declared in ` +
              `this input, so whether access to the logs is accountable cannot be evidenced here.`,
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
      // A flow log may legitimately target a subnet or an ENI, leaving vpc_id
      // absent. correlateBy treats that as naming no VPC rather than as
      // uncertainty, so one compliant subnet flow log cannot suppress the Fail
      // for every uncovered VPC in the input.
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
