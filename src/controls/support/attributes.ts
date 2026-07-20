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

/**
 * A string value, or `undefined` when there is nothing usable to read.
 *
 * Blank counts as nothing, whitespace included. Callers read an identifier, an
 * ARN or an enum — a bucket name, a VPC id, a log-group ARN, a key spec — and
 * `""` is how Terraform serialises an unset optional string, both from
 * `variable "x" { default = "" }` and from state. Returning it would let a
 * check cite `observed: ""` as its evidence of compliance, which is a Pass with
 * nothing behind it. Where absence has a meaningful default (a KMS key spec is
 * `SYMMETRIC_DEFAULT`), `undefined` is what lets the caller apply it.
 *
 * The value is returned untrimmed: only the emptiness test ignores surrounding
 * whitespace, because a name that differs by padding is a different name.
 */
export function asText(read: AttributeRead): string | undefined {
  if (read.kind !== "value" || typeof read.value !== "string" || read.value.trim() === "") {
    return undefined;
  }
  return read.value;
}
