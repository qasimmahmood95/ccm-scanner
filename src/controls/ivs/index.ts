import type { Check } from "../../engine/check.js";
import { resourcesOfType } from "../../model/resource.js";
import { fail, notApplicable, pass, type Evidence, type Finding } from "../../model/verdict.js";
import { readAttribute, unknownReason } from "../support/attributes.js";
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
      findings.push(
        notApplicable(
          `${unreadable.source}.${unreadable.attribute} is not known until apply, so whether ` +
            `it exposes a sensitive port cannot be evidenced from this input.`,
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

    for (const instance of resourcesOfType(model, "aws_db_instance")) {
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
    if (groups.length === 0) {
      return [
        notApplicable(
          `This input declares no ${DEFAULT_SG_TYPE}, so the default security group is left ` +
            `unmanaged. Its rules exist in the account but are not visible here, so whether ` +
            `it is locked down cannot be evidenced.`,
        ),
      ];
    }

    return groups.map((group): Finding => {
      const evidence: Evidence[] = [];
      let rules = 0;

      for (const attribute of ["ingress", "egress"]) {
        const read = readAttribute(group, attribute);
        if (read.kind === "unknown") {
          return notApplicable(unknownReason(group, attribute));
        }
        const declared = read.kind === "value" && Array.isArray(read.value) ? read.value : [];
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
