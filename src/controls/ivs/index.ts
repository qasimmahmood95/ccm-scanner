import type { Check } from "../../engine/check.js";
import { resourcesOfType } from "../../model/resource.js";
import { fail, notApplicable, pass, type Evidence, type Finding } from "../../model/verdict.js";
import { asText, readAttribute, unknownReason } from "../support/attributes.js";
import { correlateBy, correlatedFindings, S3_BUCKET } from "../support/correlate.js";
import {
  collectIngressRules,
  coversAllPorts,
  openToWorld,
  sensitivePortsCovered,
  SENSITIVE_PORTS,
  type IngressRule,
} from "../support/network.js";
import { PUBLIC_ACCESS_BLOCK_FLAGS, qualifiesAsFullBlock } from "../support/s3.js";

const DEFAULT_SG_TYPE = "aws_default_security_group";

/** How a world-open rule offends, phrased for the evidence entry. */
function describeExposure(rule: IngressRule): string | undefined {
  if (!openToWorld(rule)) {
    return undefined;
  }
  if (coversAllPorts(rule)) {
    return "every port open to the world";
  }
  const ports = sensitivePortsCovered(rule);
  return ports.length > 0 ? `sensitive port(s) ${ports.join(", ")} open to the world` : undefined;
}

/**
 * IVS-03 — Network Security.
 *
 * A world-open path to a remote-administration or database port is the
 * canonical network finding. Port *ranges* are tested for overlap rather than
 * equality — `from_port: 20, to_port: 25` never equals 22 but reaches it — and
 * `protocol = "-1"` opens everything regardless of the port fields.
 */
const noOpenAdminPorts: Check = {
  checkId: "ivs/no-open-admin-ports",
  ccmId: "IVS-03",
  ccmTitle: "Network Security",
  run: (model) => {
    const scan = collectIngressRules(model);
    const findings: Finding[] = [];

    for (const unreadable of scan.unreadable) {
      const why = {
        unknown: "is not known until apply",
        unreadable: "could not be read",
        unrecognised: "names a protocol this scanner does not classify",
      }[unreadable.cause];
      findings.push(
        notApplicable(
          `${unreadable.source}.${unreadable.attribute} ${why}, so whether it exposes a ` +
            `sensitive port cannot be evidenced from this input.`,
        ),
      );
    }

    const offending = scan.rules.flatMap((rule) => {
      const exposure = describeExposure(rule);
      return exposure === undefined ? [] : [{ rule, exposure }];
    });

    if (offending.length > 0) {
      findings.push(
        fail(
          offending.map(({ rule, exposure }): Evidence => ({
            resourceAddress: rule.source,
            attribute: rule.attribute,
            observed: {
              protocol: rule.protocol,
              from_port: rule.fromPort ?? null,
              to_port: rule.toPort ?? null,
              cidrs: rule.cidrs,
              exposure,
            },
            expected: `no ingress from 0.0.0.0/0 or ::/0 to ports ${SENSITIVE_PORTS.join(", ")}`,
          })),
        ),
      );
    } else if (scan.rules.length > 0) {
      findings.push(
        pass(
          scan.rules.map((rule): Evidence => ({
            resourceAddress: rule.source,
            attribute: rule.attribute,
            observed: {
              protocol: rule.protocol,
              from_port: rule.fromPort ?? null,
              to_port: rule.toPort ?? null,
              cidrs: rule.cidrs,
            },
            expected: `no ingress from 0.0.0.0/0 or ::/0 to ports ${SENSITIVE_PORTS.join(", ")}`,
          })),
        ),
      );
    }

    if (findings.length === 0) {
      return [notApplicable("This input declares no security-group ingress rules to inspect.")];
    }
    return findings;
  },
};

/**
 * IVS-03 — Network Security (public exposure).
 *
 * The other half of the same control: a resource does not need an open port to
 * be reachable by anyone. A bucket without a full public-access block, or an
 * RDS instance with a public endpoint, is exposed by configuration alone.
 */
const publicExposure: Check = {
  checkId: "ivs/s3-public-access-block",
  ccmId: "IVS-03",
  ccmTitle: "Network Security",
  run: (model) => {
    const findings: Finding[] = [];

    if (resourcesOfType(model, S3_BUCKET.type).length > 0) {
      findings.push(
        ...correlatedFindings(
          model,
          S3_BUCKET,
          correlateBy(model, "aws_s3_bucket_public_access_block", "bucket", (block) =>
            qualifiesAsFullBlock(block),
          ),
          (covered, name) => ({
            attribute: "bucket",
            observed: covered
              ? "covered by a public-access block with all four flags enabled"
              : `no aws_s3_bucket_public_access_block enables all four flags for "${name}"`,
            expected: `all of ${PUBLIC_ACCESS_BLOCK_FLAGS.join(", ")} set to true`,
          }),
        ),
      );
    }

    // Aurora puts the endpoint on the cluster's instances, not on the cluster,
    // so omitting this type would let a publicly-addressable Aurora instance
    // scan clean.
    for (const type of ["aws_db_instance", "aws_rds_cluster_instance"]) {
      for (const instance of resourcesOfType(model, type)) {
        const read = readAttribute(instance, "publicly_accessible");
        if (read.kind === "unknown") {
          findings.push(notApplicable(unknownReason(instance, "publicly_accessible")));
          continue;
        }
        // Terraform defaults this to false, so absent is a genuine "not public".
        const value = read.kind === "value" ? read.value : false;
        const evidence: Evidence[] = [
          {
            resourceAddress: instance.address,
            attribute: "publicly_accessible",
            observed: value,
            expected: "false",
          },
        ];
        findings.push(value === true ? fail(evidence) : pass(evidence));
      }
    }

    if (findings.length === 0) {
      return [
        notApplicable(
          "This input declares no S3 buckets or RDS instances whose public exposure is visible.",
        ),
      ];
    }
    return findings;
  },
};

/**
 * IVS-06 — Segmentation and Segregation.
 *
 * The default security group is attached to anything that does not name one,
 * so a rule on it is a rule nobody chose. Terraform's
 * `aws_default_security_group` *adopts* the existing group and replaces its
 * rules, which is why declaring it with no blocks is the way to lock it down.
 *
 * An input that does not manage the default SG is not evidence either way: the
 * group still exists in the account with whatever rules it has.
 */
const defaultSgLockedDown: Check = {
  checkId: "ivs/default-sg-locked-down",
  ccmId: "IVS-06",
  ccmTitle: "Segmentation and Segregation",
  run: (model) => {
    const groups = resourcesOfType(model, DEFAULT_SG_TYPE);
    const vpcs = resourcesOfType(model, "aws_vpc");
    if (groups.length === 0 && vpcs.length === 0) {
      return [
        notApplicable(
          `This input declares no ${DEFAULT_SG_TYPE} and no VPC, so the default security ` +
            `group is left unmanaged. Its rules exist in the account but are not visible ` +
            `here, so whether it is locked down cannot be evidenced.`,
        ),
      ];
    }

    const findings: Finding[] = groups.map((group): Finding => {
      const evidence: Evidence[] = [];
      let rules = 0;

      for (const attribute of ["ingress", "egress"]) {
        const read = readAttribute(group, attribute);
        if (read.kind === "unknown") {
          return notApplicable(unknownReason(group, attribute));
        }
        // A present-but-non-array value is not "no rules" — saying so would be
        // evidence asserting something the input never said.
        if (read.kind === "value" && !Array.isArray(read.value)) {
          return notApplicable(
            `${group.address}.${attribute} is not a list of rules, so whether the default ` +
              `security group carries any cannot be evidenced.`,
          );
        }
        const declared = read.kind === "value" ? (read.value as readonly unknown[]) : [];
        rules += declared.length;
        evidence.push({
          resourceAddress: group.address,
          attribute,
          observed: declared.length === 0 ? "no rules" : declared,
          expected: "no rules",
        });
      }

      return rules > 0 ? fail(evidence) : pass(evidence);
    });

    // A VPC created here whose default group is never adopted is not a silent
    // pass: AWS creates that group with allow-all-from-itself ingress and
    // allow-all egress, and this input neither replaces nor shows them.
    //
    // Matching is by id, and a create plan knows neither side's id — so when
    // any is unknown we fall back to counting. More VPCs than adopted groups
    // means at least one is unmanaged whichever way they pair up, which is
    // evidenced; naming a specific VPC there would not be. Reporting a VPC as
    // unevidenceable while the group beside it just passed would contradict
    // the finding we already made.
    const identified = vpcs.map((vpc) => ({
      vpc,
      id: asText(readAttribute(vpc, "id")),
      unknownId: readAttribute(vpc, "id").kind === "unknown",
    }));
    const adoptions = groups.map((group) => ({
      group,
      vpcId: asText(readAttribute(group, "vpc_id")),
      unknownVpcId: readAttribute(group, "vpc_id").kind === "unknown",
      // vpc_id is Optional: omitting it adopts the default VPC's group, so
      // absent is ordinary input rather than a malformed resource.
      absentVpcId: readAttribute(group, "vpc_id").kind === "absent",
    }));
    const allResolvable =
      identified.every((entry) => entry.id !== undefined) &&
      adoptions.every((entry) => entry.vpcId !== undefined);

    if (allResolvable) {
      const adopted = new Set(adoptions.map((entry) => entry.vpcId));
      for (const { vpc, id } of identified) {
        if (id !== undefined && adopted.has(id)) {
          continue;
        }
        findings.push(
          notApplicable(
            `${vpc.address} declares no ${DEFAULT_SG_TYPE}, so its default security group ` +
              `keeps the rules AWS created it with — allow-all from itself, and allow-all ` +
              `egress. Those rules are not visible here, so this is reported rather than failed.`,
          ),
        );
      }
      return findings;
    }

    // Ids could not all be resolved, so VPCs cannot be matched to the groups
    // that adopt them and no individual VPC can be named. Counting still
    // evidences something: a group whose vpc_id resolves to an id no declared
    // VPC carries adopts a VPC from somewhere else and offsets nothing here.
    const declaredIds = new Set(identified.flatMap((entry) => (entry.id ? [entry.id] : [])));
    // Count VPCs *covered*, not groups declared: two groups naming the same VPC
    // adopt one default group between them, and counting them as two would
    // silently absorb a second, unmanaged VPC.
    const matched = new Set(
      adoptions.flatMap((entry) =>
        entry.vpcId !== undefined && declaredIds.has(entry.vpcId) ? [entry.vpcId] : [],
      ),
    );
    const unmatchable = adoptions.filter((entry) => entry.vpcId === undefined).length;
    const offsetting = matched.size + unmatchable;

    if (vpcs.length > offsetting) {
      // Name the cause honestly: unknown-until-apply, simply absent, and
      // present-but-unreadable are three different things, and the reason must
      // not assert the wrong one — nor blame the VPCs when it was the group's
      // pointer that did not resolve.
      const unknownSide = identified.some((entry) => entry.unknownId)
        ? "their ids are not known until apply"
        : adoptions.some((entry) => entry.unknownVpcId)
          ? `a ${DEFAULT_SG_TYPE}'s vpc_id is not known until apply`
          : adoptions.some((entry) => entry.absentVpcId)
            ? `a ${DEFAULT_SG_TYPE} declares no vpc_id, so which VPC it adopts is not stated`
            : "the ids could not be read";
      findings.push(
        notApplicable(
          `This input declares ${String(vpcs.length)} VPC(s) but only ${String(offsetting)} ` +
            `${DEFAULT_SG_TYPE} that could adopt one, so at least ` +
            `${String(vpcs.length - offsetting)} default security group(s) keep the rules AWS ` +
            `created them with. Which VPCs cannot be said: ${unknownSide}, so they cannot be ` +
            `matched to the groups that adopt them.`,
        ),
      );
    }

    return findings;
  },
};

/** IVS-04 — OS Hardening and Base Controls. Below the infrastructure graph. */
const osHardening: Check = {
  checkId: "ivs/na-host-config",
  ccmId: "IVS-04",
  ccmTitle: "OS Hardening and Base Controls",
  run: () => [
    notApplicable(
      "OS and AMI hardening lives inside the image or host. An instance declaration names " +
        "an AMI but carries no signal of how that image was built or configured.",
    ),
  ],
};

/** IVS-08 — Network Architecture Documentation. A documentation deliverable. */
const networkDocumentation: Check = {
  checkId: "ivs/na-documentation",
  ccmId: "IVS-08",
  ccmTitle: "Network Architecture Documentation",
  run: () => [
    notApplicable(
      "Network architecture documentation is a written deliverable reviewed by people. " +
        "No resource attribute evidences whether it exists or is current.",
    ),
  ],
};

export const ivsChecks: readonly Check[] = [
  defaultSgLockedDown,
  networkDocumentation,
  osHardening,
  noOpenAdminPorts,
  publicExposure,
];
