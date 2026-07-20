/**
 * The provider-agnostic resource model that checks consume.
 *
 * Adapters (Terraform plan JSON, HCL, cloud snapshot) are the only code that
 * knows about input formats; they all normalise into this shape so a check runs
 * unchanged over any of them.
 */

/** A single infrastructure resource. */
export interface Resource {
  /** Unique address, e.g. `aws_security_group.web`. */
  readonly address: string;
  /** Resource type, e.g. `aws_security_group`. */
  readonly type: string;
  /** Local name, e.g. `web`. */
  readonly name: string;
  /** Provider short name, e.g. `aws`. */
  readonly provider: string;
  /** Raw attributes as normalised from the input. */
  readonly attributes: Readonly<Record<string, unknown>>;
  /**
   * Attributes whose value Terraform cannot know until apply.
   *
   * A plan writes these as `null` or omits them, making them
   * indistinguishable from "not configured" — so a check that reads such an
   * attribute as absent would be guessing. Consult this list first and report
   * `not_applicable` instead (hard constraint 5).
   */
  readonly unknownAttributes: readonly string[];
  /**
   * Attributes Terraform marks sensitive. `terraform show -json` of *state*
   * puts real secrets in `values`, and the report is an artifact people commit
   * and share, so renderers must redact these rather than print them.
   */
  readonly sensitiveAttributes: readonly string[];
}

/** The infrastructure under audit. */
export interface ResourceModel {
  /** Where this model came from, e.g. `terraform-show:plan.json`. */
  readonly source: string;
  readonly resources: readonly Resource[];
}

/** All resources of a given type, in model order. */
export function resourcesOfType(model: ResourceModel, type: string): readonly Resource[] {
  return model.resources.filter((resource) => resource.type === type);
}

/** The resource at `address`, or `undefined` when absent. */
export function findResource(model: ResourceModel, address: string): Resource | undefined {
  return model.resources.find((resource) => resource.address === address);
}

/**
 * True when the attribute's value is not knowable from this input, so a check
 * must report `not_applicable` rather than infer anything from its absence.
 *
 * Accepts a nested path as well as a bare name — a check reading
 * `ingress[0].cidr_blocks` is asking about the `ingress` attribute, and
 * Terraform marks unknown-ness at the top level.
 */
export function isUnknown(resource: Resource, attribute: string): boolean {
  const [topLevel] = attribute.split(/[.[]/, 1);
  return resource.unknownAttributes.includes(topLevel ?? attribute);
}

/** An empty model — useful for tests and for inputs that declare no resources. */
export function emptyModel(source: string): ResourceModel {
  return { source, resources: [] };
}
