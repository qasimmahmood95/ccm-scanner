import type { Resource, ResourceModel } from "../model/resource.js";
import { compareStrings } from "../util/compare.js";
import { IngestError } from "./errors.js";
import { asArray, asString, isRecord } from "./json.js";

/**
 * Ingests `terraform show -json` / `terraform plan -json` output.
 *
 * Read-only by construction: this parses a JSON document that the operator
 * produced. It never invokes Terraform and never touches cloud state.
 */

export interface IngestResult {
  readonly model: ResourceModel;
  /** Non-fatal notes (skipped entries, ambiguous input) surfaced, never guessed away. */
  readonly warnings: readonly string[];
}

/** `registry.terraform.io/hashicorp/aws` -> `aws`. */
function shortProvider(providerName: string | undefined): string {
  if (providerName === undefined || providerName === "") {
    return "unknown";
  }
  const parts = providerName.split("/");
  return parts[parts.length - 1] ?? "unknown";
}

function walkModule(module: unknown, resources: Resource[], warnings: string[]): void {
  if (!isRecord(module)) {
    return;
  }

  for (const entry of asArray(module.resources)) {
    if (!isRecord(entry)) {
      warnings.push("skipped a resource entry that was not an object");
      continue;
    }

    // Data sources describe lookups, not infrastructure we can hold to account.
    const mode = asString(entry.mode) ?? "managed";
    if (mode !== "managed") {
      continue;
    }

    const address = asString(entry.address);
    const type = asString(entry.type);
    const name = asString(entry.name);
    if (address === undefined || type === undefined || name === undefined) {
      warnings.push("skipped a managed resource missing address, type or name");
      continue;
    }

    resources.push({
      address,
      type,
      name,
      provider: shortProvider(asString(entry.provider_name)),
      attributes: isRecord(entry.values) ? entry.values : {},
    });
  }

  for (const child of asArray(module.child_modules)) {
    walkModule(child, resources, warnings);
  }
}

export function ingestTerraformPlan(raw: string, source: string): IngestResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new IngestError(source, "input is not valid JSON");
  }

  if (!isRecord(parsed)) {
    throw new IngestError(source, "expected a JSON object at the document root");
  }

  const warnings: string[] = [];

  // `terraform plan -json` exposes planned_values; `terraform show -json` of
  // state exposes values. Support both, preferring the plan.
  const planned = isRecord(parsed.planned_values) ? parsed.planned_values : undefined;
  const state = isRecord(parsed.values) ? parsed.values : undefined;
  const container = planned ?? state;

  if (container === undefined) {
    throw new IngestError(
      source,
      'no "planned_values" or "values" found — is this `terraform show -json` output?',
    );
  }
  if (planned !== undefined && state !== undefined) {
    warnings.push('input contains both "planned_values" and "values"; using "planned_values"');
  }

  const resources: Resource[] = [];
  walkModule(container.root_module, resources, warnings);

  if (resources.length === 0) {
    warnings.push("no managed resources found in the input");
  }

  // Sort by address so the model — and therefore the report — does not depend
  // on the order Terraform happened to emit.
  resources.sort((a, b) => compareStrings(a.address, b.address));

  return { model: { source, resources }, warnings };
}
