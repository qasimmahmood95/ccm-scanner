import type { Resource, ResourceModel } from "../model/resource.js";
import { compareStrings } from "../util/compare.js";
import { IngestError } from "./errors.js";
import { asArray, asString, isRecord } from "./json.js";

/**
 * Ingests `terraform show -json` output — either of a saved plan file
 * (`terraform plan -out=tfplan && terraform show -json tfplan`) or of state
 * (`terraform show -json`).
 *
 * Note this is NOT `terraform plan -json`, which emits a newline-delimited
 * stream of log messages rather than the plan representation.
 *
 * Read-only by construction: this takes the document as a string, so the
 * adapter cannot reach the filesystem, let alone Terraform or a cloud API.
 */

export interface IngestResult {
  readonly model: ResourceModel;
  /** Non-fatal notes (skipped entries, ambiguous input) surfaced, never guessed away. */
  readonly warnings: readonly string[];
}

interface WalkContext {
  readonly resources: Resource[];
  readonly warnings: string[];
  readonly unknownByAddress: ReadonlyMap<string, readonly string[]>;
  readonly seenAddresses: Set<string>;
}

/** `registry.terraform.io/hashicorp/aws` -> `aws`. */
function shortProvider(providerName: string | undefined): string {
  if (providerName === undefined) {
    return "unknown";
  }
  const parts = providerName.split("/");
  const last = parts[parts.length - 1];
  return last === undefined || last === "" ? "unknown" : last;
}

/** True when any leaf in the subtree is `true`. */
function containsTrue(value: unknown): boolean {
  if (value === true) {
    return true;
  }
  if (Array.isArray(value)) {
    return value.some(containsTrue);
  }
  if (isRecord(value)) {
    return Object.values(value).some(containsTrue);
  }
  return false;
}

/**
 * Top-level attribute names flagged in a Terraform marker map such as
 * `after_unknown` or `sensitive_values`, which mirror the attribute shape and
 * carry `true` at the marked leaves. An attribute is reported when anything
 * beneath it is marked — partially unknown is still not fully known.
 */
function markedAttributes(marker: unknown): readonly string[] {
  if (!isRecord(marker)) {
    return [];
  }
  return Object.keys(marker)
    .filter((key) => containsTrue(marker[key]))
    .sort(compareStrings);
}

/**
 * Which attributes of which resources are unknown until apply.
 *
 * `planned_values` writes unknown values as `null` or omits them, so this map —
 * built from `resource_changes[].change.after_unknown` — is the only thing that
 * distinguishes "will be computed" from "not configured". Ingest is the only
 * layer that can see it.
 */
function unknownByAddress(parsed: Record<string, unknown>): ReadonlyMap<string, readonly string[]> {
  const map = new Map<string, readonly string[]>();
  for (const entry of asArray(parsed.resource_changes)) {
    if (!isRecord(entry)) {
      continue;
    }
    const address = asString(entry.address);
    if (address === undefined || !isRecord(entry.change)) {
      continue;
    }
    const unknown = markedAttributes(entry.change.after_unknown);
    if (unknown.length > 0) {
      map.set(address, unknown);
    }
  }
  return map;
}

function walkModule(module: unknown, path: string, context: WalkContext): void {
  if (!isRecord(module)) {
    context.warnings.push(`skipped ${path}, which was not an object`);
    return;
  }

  if (module.resources !== undefined && !Array.isArray(module.resources)) {
    context.warnings.push(`skipped ${path}.resources, which was not an array`);
  }

  for (const entry of asArray(module.resources)) {
    if (!isRecord(entry)) {
      context.warnings.push("skipped a resource entry that was not an object");
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
      context.warnings.push("skipped a managed resource missing address, type or name");
      continue;
    }

    if (context.seenAddresses.has(address)) {
      context.warnings.push(`skipped a duplicate resource address: ${address}`);
      continue;
    }
    context.seenAddresses.add(address);

    if (entry.values !== undefined && !isRecord(entry.values)) {
      context.warnings.push(`${address} has a non-object "values"; treating it as no attributes`);
    }

    context.resources.push({
      address,
      type,
      name,
      provider: shortProvider(asString(entry.provider_name)),
      attributes: isRecord(entry.values) ? entry.values : {},
      unknownAttributes: context.unknownByAddress.get(address) ?? [],
      sensitiveAttributes: markedAttributes(entry.sensitive_values),
    });
  }

  const children = asArray(module.child_modules);
  for (const [index, child] of children.entries()) {
    walkModule(child, `${path}.child_modules[${String(index)}]`, context);
  }
}

/** `terraform plan -json` emits NDJSON log lines; each carries an `@level` field. */
function looksLikeLogStream(raw: string): boolean {
  const firstLine = raw.slice(0, 2000).split("\n", 1)[0] ?? "";
  return firstLine.includes('"@level"') || firstLine.includes('"@message"');
}

export function ingestTerraformPlan(raw: string, source: string): IngestResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    if (looksLikeLogStream(raw)) {
      throw new IngestError(
        source,
        "this looks like `terraform plan -json`, which is a newline-delimited log stream " +
          "rather than a plan representation. Use `terraform plan -out=tfplan && " +
          "terraform show -json tfplan`",
      );
    }
    throw new IngestError(source, "input is not valid JSON");
  }

  if (!isRecord(parsed)) {
    throw new IngestError(source, "expected a JSON object at the document root");
  }

  const warnings: string[] = [];

  // `terraform show -json` of a plan file exposes planned_values; of state, values.
  const planned = isRecord(parsed.planned_values) ? parsed.planned_values : undefined;
  const state = isRecord(parsed.values) ? parsed.values : undefined;
  const container = planned ?? state;

  if (container === undefined) {
    // A document carrying a Terraform version marker really is Terraform
    // output — it just has nothing to audit, which is not the same as being
    // handed the wrong file.
    const isTerraformOutput =
      asString(parsed.format_version) !== undefined ||
      asString(parsed.terraform_version) !== undefined;
    if (isTerraformOutput) {
      return {
        model: { source, resources: [] },
        warnings: ['input has no "planned_values" or "values" — nothing to audit'],
      };
    }
    throw new IngestError(
      source,
      'no "planned_values" or "values" found — is this `terraform show -json` output?',
    );
  }
  if (planned !== undefined && state !== undefined) {
    warnings.push('input contains both "planned_values" and "values"; using "planned_values"');
  }

  const context: WalkContext = {
    resources: [],
    warnings,
    unknownByAddress: unknownByAddress(parsed),
    seenAddresses: new Set<string>(),
  };
  walkModule(container.root_module, "root_module", context);

  if (context.resources.length === 0) {
    warnings.push("no managed resources found in the input");
  }

  // Sort by address so the model — and therefore the report — does not depend
  // on the order Terraform happened to emit.
  context.resources.sort((a, b) => compareStrings(a.address, b.address));

  return { model: { source, resources: context.resources }, warnings };
}
