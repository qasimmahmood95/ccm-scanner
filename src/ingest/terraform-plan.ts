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

/**
 * Terraform nests modules and attribute markers, but not deeply. A cap keeps a
 * pathological document from overflowing the stack with a `RangeError` that
 * would escape this adapter's own error type.
 */
const MAX_DEPTH = 100;

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
function containsTrue(value: unknown, depth: number): boolean {
  if (value === true) {
    return true;
  }
  if (depth >= MAX_DEPTH) {
    return false;
  }
  if (Array.isArray(value)) {
    return value.some((entry) => containsTrue(entry, depth + 1));
  }
  if (isRecord(value)) {
    return Object.values(value).some((entry) => containsTrue(entry, depth + 1));
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
    .filter((key) => containsTrue(marker[key], 0))
    .sort(compareStrings);
}

function mergeSorted(a: readonly string[], b: readonly string[]): readonly string[] {
  return [...new Set([...a, ...b])].sort(compareStrings);
}

/**
 * Which attributes of which resources are unknown until apply.
 *
 * `planned_values` writes unknown values as `null` or omits them, so this map —
 * built from `resource_changes[].change.after_unknown` — is the only thing that
 * distinguishes "will be computed" from "not configured". Ingest is the only
 * layer that can see it, so anything that stops us reading it is warned about
 * rather than passed over: a check that mistakes unknown for absent will emit
 * an evidenced-looking verdict it has no basis for.
 */
function unknownByAddress(
  parsed: Record<string, unknown>,
  warnings: string[],
): ReadonlyMap<string, readonly string[]> {
  const map = new Map<string, readonly string[]>();

  if (parsed.resource_changes !== undefined && !Array.isArray(parsed.resource_changes)) {
    warnings.push(
      'skipped "resource_changes", which was not an array; unknown-until-apply values ' +
        "cannot be identified",
    );
    return map;
  }

  for (const entry of asArray(parsed.resource_changes)) {
    if (!isRecord(entry)) {
      warnings.push('skipped a "resource_changes" entry that was not an object');
      continue;
    }
    const address = asString(entry.address);
    if (address === undefined) {
      warnings.push('skipped a "resource_changes" entry with no address');
      continue;
    }
    if (!isRecord(entry.change)) {
      warnings.push(`"resource_changes" entry for ${address} has no usable "change"`);
      continue;
    }

    const afterUnknown = entry.change.after_unknown;
    if (afterUnknown === true) {
      warnings.push(
        `every attribute of ${address} is unknown until apply, but they cannot be ` +
          "enumerated from this input",
      );
      continue;
    }
    if (afterUnknown !== undefined && afterUnknown !== false && !isRecord(afterUnknown)) {
      warnings.push(`"resource_changes" entry for ${address} has an unusable "after_unknown"`);
      continue;
    }

    const unknown = markedAttributes(afterUnknown);
    if (unknown.length > 0) {
      // A resource can appear more than once (the replace/deposed shape), so
      // merge rather than let the last entry win.
      map.set(address, mergeSorted(map.get(address) ?? [], unknown));
    }
  }
  return map;
}

function walkModule(module: unknown, path: string, depth: number, context: WalkContext): void {
  if (depth >= MAX_DEPTH) {
    context.warnings.push(
      `stopped at ${path}: module nesting exceeded ${String(MAX_DEPTH)} levels`,
    );
    return;
  }
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

  // Guarded for the same reason as `resources` above: a non-array here would
  // silently discard every resource nested beneath it, and the caller would
  // see a complete-looking model with an empty warning list.
  if (module.child_modules !== undefined && !Array.isArray(module.child_modules)) {
    context.warnings.push(`skipped ${path}.child_modules, which was not an array`);
    return;
  }

  for (const [index, child] of asArray(module.child_modules).entries()) {
    walkModule(child, `${path}.child_modules[${String(index)}]`, depth + 1, context);
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
    unknownByAddress: unknownByAddress(parsed, warnings),
    seenAddresses: new Set<string>(),
  };
  walkModule(container.root_module, "root_module", 0, context);

  if (context.resources.length === 0) {
    warnings.push("no managed resources found in the input");
  }

  // Sort by address so the model — and therefore the report — does not depend
  // on the order Terraform happened to emit.
  context.resources.sort((a, b) => compareStrings(a.address, b.address));

  return { model: { source, resources: context.resources }, warnings };
}
