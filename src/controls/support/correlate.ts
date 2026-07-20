/**
 * Correlating a subject resource with the satellite resources that configure it.
 *
 * Terraform splits a great deal of configuration across resources that point
 * back at their subject by id or name: encryption, public-access blocking and
 * logging all live outside `aws_s3_bucket`, and a VPC's flow log lives outside
 * `aws_vpc`. The correlator is routinely `aws_s3_bucket.x.id` or
 * `aws_vpc.main.id`, which a create plan reports as unknown until apply.
 *
 * Treating an unresolvable correlator as "nothing configures this subject"
 * would fail a resource that is in fact compliant, so the distinction is
 * carried all the way through to the verdict: unresolved becomes
 * not-applicable with a reason, never a Fail (hard constraint 5).
 */
import { resourcesOfType, type Resource, type ResourceModel } from "../../model/resource.js";
import { fail, notApplicable, pass, type Evidence, type Finding } from "../../model/verdict.js";
import { asText, readAttribute, unknownReason } from "./attributes.js";

/** Why a correlator could not be resolved — the reason must not misdescribe it. */
export type Cause = "unknown" | "unreadable";

export interface Unresolvable {
  readonly what: string;
  readonly cause: Cause;
  /**
   * The subject this uncertainty applies to, when we resolved it.
   *
   * An unknown flag on *one* bucket's public-access block says nothing about
   * any other bucket, so without this every subject of the type would be
   * reported not-applicable because of an unrelated resource. `undefined` means
   * we could not tell which subject it belonged to, and it does apply broadly.
   */
  readonly subjectKey?: string;
}

/** Subject keys that satisfy some control, plus the correlators we could not resolve. */
export interface Correlation {
  readonly keys: ReadonlySet<string>;
  readonly unresolvable: readonly Unresolvable[];
}

/**
 * Whether a satellite resource satisfies the control for its subject.
 * `unresolvable` is distinct from `no`: it means the input cannot tell us,
 * which must become not-applicable rather than a failure.
 */
export type Qualification =
  | { readonly kind: "yes" }
  | { readonly kind: "no" }
  | { readonly kind: "unresolvable"; readonly attribute: string; readonly cause: Cause };

export function describeUnresolvable(entries: readonly Unresolvable[]): string {
  return entries
    .map((entry) =>
      entry.cause === "unknown"
        ? `${entry.what} is not known until apply`
        : `${entry.what} could not be read`,
    )
    .join("; ");
}

/**
 * What an *absent* key attribute means for this satellite type.
 *
 * For an S3 satellite, a missing `bucket` is malformed input — we cannot say
 * the bucket is unconfigured, so it counts as uncertainty. But an
 * `aws_flow_log` may legitimately target a subnet or an ENI instead of a VPC,
 * and then `vpc_id` is simply absent. Reading that as uncertainty lets one
 * compliant subnet flow log suppress the Fail for every uncovered VPC.
 */
export type AbsentKey = "skip" | "unresolvable";

/**
 * Collects the subject keys covered by satellites of `type`.
 *
 * `keyAttribute` is the satellite's pointer back at its subject —
 * `aws_s3_bucket_policy.bucket`, `aws_flow_log.vpc_id`.
 */
export function correlateBy(
  model: ResourceModel,
  type: string,
  keyAttribute: string,
  qualifies: (resource: Resource, key: string) => Qualification,
  absentKey: AbsentKey = "unresolvable",
): Correlation {
  const keys = new Set<string>();
  const unresolvable: Unresolvable[] = [];

  for (const resource of resourcesOfType(model, type)) {
    const read = readAttribute(resource, keyAttribute);
    if (read.kind === "absent" && absentKey === "skip") {
      // Not a satellite of this subject kind at all.
      continue;
    }
    const key = read.kind === "unknown" ? undefined : asText(read);
    if (key === undefined) {
      unresolvable.push({
        what: `${resource.address}.${keyAttribute}`,
        cause: read.kind === "unknown" ? "unknown" : "unreadable",
      });
      continue;
    }
    const qualification = qualifies(resource, key);
    if (qualification.kind === "yes") {
      keys.add(key);
    } else if (qualification.kind === "unresolvable") {
      // The subject resolved, so this uncertainty is confined to it.
      unresolvable.push({
        what: `${resource.address}.${qualification.attribute}`,
        cause: qualification.cause,
        subjectKey: key,
      });
    }
  }
  return { keys, unresolvable };
}

/** The uncertainty that actually bears on one subject. */
function blockingFor(correlation: Correlation, key: string): readonly Unresolvable[] {
  return correlation.unresolvable.filter(
    (entry) => entry.subjectKey === undefined || entry.subjectKey === key,
  );
}

/** A subject type and the attribute that identifies it to its satellites. */
export interface Subject {
  readonly type: string;
  /** e.g. `bucket` on `aws_s3_bucket`, `id` on `aws_vpc`. */
  readonly keyAttribute: string;
  /** Singular noun for the reason text, e.g. `bucket`, `VPC`. */
  readonly noun: string;
  /** How to name the key in a reason, e.g. `bucket name`, `id`. */
  readonly keyNoun: string;
}

/** One finding per subject: covered is a Pass, uncorrelatable is not-applicable. */
export function correlatedFindings(
  model: ResourceModel,
  subject: Subject,
  correlation: Correlation,
  describe: (covered: boolean, key: string) => Omit<Evidence, "resourceAddress">,
): readonly Finding[] {
  return resourcesOfType(model, subject.type).map((resource): Finding => {
    const read = readAttribute(resource, subject.keyAttribute);
    if (read.kind === "unknown") {
      return notApplicable(unknownReason(resource, subject.keyAttribute));
    }
    const key = asText(read);
    if (key === undefined) {
      return notApplicable(
        `${resource.address} has no resolvable ${subject.keyNoun}, so its configuration ` +
          `cannot be correlated.`,
      );
    }
    const covered = correlation.keys.has(key);
    const blocking = blockingFor(correlation, key);
    if (!covered && blocking.length > 0) {
      return notApplicable(
        `${resource.address} cannot be correlated: ` +
          `${describeUnresolvable(blocking)}, so a configuration targeting ` +
          `this ${subject.noun} may exist without being visible here.`,
      );
    }
    const evidence: Evidence = { resourceAddress: resource.address, ...describe(covered, key) };
    return covered ? pass([evidence]) : fail([evidence]);
  });
}

/**
 * Whether one *named* subject is covered — for controls that start from another
 * resource (a trail naming its log bucket) rather than from the subject list.
 *
 * `undeclared` is its own outcome and must not collapse into `uncovered`: a
 * bucket named by a trail but created in a different module tells us nothing
 * about how it is configured, so it cannot be a Fail.
 */
export type Coverage =
  /** `address` is the subject resource, so evidence can cite it rather than the caller. */
  | { readonly kind: "covered"; readonly address: string }
  | { readonly kind: "uncovered"; readonly address: string }
  | { readonly kind: "undeclared" }
  | { readonly kind: "unresolvable"; readonly detail: string };

export function coverageOf(
  model: ResourceModel,
  subject: Subject,
  correlation: Correlation,
  key: string,
): Coverage {
  const declared = resourcesOfType(model, subject.type).find(
    (resource) => asText(readAttribute(resource, subject.keyAttribute)) === key,
  );
  if (declared === undefined) {
    return { kind: "undeclared" };
  }
  if (correlation.keys.has(key)) {
    return { kind: "covered", address: declared.address };
  }
  const blocking = blockingFor(correlation, key);
  if (blocking.length > 0) {
    return { kind: "unresolvable", detail: describeUnresolvable(blocking) };
  }
  return { kind: "uncovered", address: declared.address };
}

export const S3_BUCKET: Subject = {
  type: "aws_s3_bucket",
  keyAttribute: "bucket",
  noun: "bucket",
  keyNoun: "bucket name",
};

export const VPC: Subject = {
  type: "aws_vpc",
  keyAttribute: "id",
  noun: "VPC",
  keyNoun: "id",
};
