import { isUnknown, type Resource } from "../../model/resource.js";

/**
 * Reading an attribute has three outcomes, and conflating them is how a
 * scanner starts guessing.
 *
 * Terraform writes a value it cannot compute until apply as `null`, which is
 * byte-identical to "the operator never set it". The ingest layer preserves the
 * distinction on `Resource.unknownAttributes`; this is where checks consume it.
 */
export type AttributeRead =
  | { readonly kind: "value"; readonly value: unknown }
  | { readonly kind: "unknown" }
  | { readonly kind: "absent" };

export function readAttribute(resource: Resource, name: string): AttributeRead {
  if (isUnknown(resource, name)) {
    return { kind: "unknown" };
  }
  const value = resource.attributes[name];
  if (value === undefined || value === null) {
    return { kind: "absent" };
  }
  return { kind: "value", value };
}

/** A reason string for the `unknown` case, phrased for an auditor. */
export function unknownReason(resource: Resource, attribute: string): string {
  return (
    `${resource.address}.${attribute} is not known until apply, so this input cannot ` +
    `evidence the control either way`
  );
}

export function asNumber(read: AttributeRead): number | undefined {
  return read.kind === "value" && typeof read.value === "number" ? read.value : undefined;
}

export function asText(read: AttributeRead): string | undefined {
  return read.kind === "value" && typeof read.value === "string" ? read.value : undefined;
}
