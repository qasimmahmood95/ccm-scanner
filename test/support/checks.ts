import { allChecks } from "../../src/controls/index.js";
import type { Finding, Resource, ResourceModel, Status } from "../../src/index.js";

/** Builders for the hand-made models the boundary suites run checks against. */

export function resource(
  address: string,
  type: string,
  attributes: Record<string, unknown> = {},
  unknownAttributes: readonly string[] = [],
): Resource {
  return {
    address,
    type,
    name: address.split(".").pop() ?? address,
    provider: "aws",
    attributes,
    unknownAttributes,
    sensitiveAttributes: [],
  };
}

export function model(...resources: Resource[]): ResourceModel {
  return { source: "memory:boundary-test", resources };
}

export function run(checkId: string, input: ResourceModel): readonly Finding[] {
  const check = allChecks.find((candidate) => candidate.checkId === checkId);
  if (check === undefined) {
    throw new Error(`no check registered as "${checkId}"`);
  }
  return check.run(input);
}

/** The single status a check yields for a one-resource model. */
export function statusOf(checkId: string, input: ResourceModel): Status | undefined {
  return run(checkId, input)[0]?.status;
}

/** Every status a check yields, for models that produce several findings. */
export function statusesOf(checkId: string, input: ResourceModel): readonly Status[] {
  return run(checkId, input).map((finding) => finding.status);
}
