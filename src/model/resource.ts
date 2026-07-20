/**
 * The provider-agnostic resource model that checks consume.
 *
 * Adapters (Terraform plan JSON, HCL, cloud snapshot) are the only code that
 * knows about input formats; they all normalise into this shape so a check runs
 * unchanged over any of them. Populated by the ingest layer in M2.
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
}

/** The infrastructure under audit. */
export interface ResourceModel {
  /** Where this model came from, e.g. `terraform-plan:plan.json`. */
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

/** An empty model — useful for tests and for inputs that declare no resources. */
export function emptyModel(source: string): ResourceModel {
  return { source, resources: [] };
}
