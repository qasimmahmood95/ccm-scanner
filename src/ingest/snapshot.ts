/**
 * Ingesting a read-only cloud snapshot.
 *
 * The checks consume `ResourceModel` and nothing else, so the same check runs
 * unchanged over Terraform and over observed cloud state. What differs is where
 * the model comes from — and one difference matters enough to state plainly:
 *
 * **A snapshot has no unknown-until-apply.** Terraform writes a value it cannot
 * compute yet as `null`, and the whole `unknownAttributes` mechanism exists to
 * stop a check reading that as "not configured". A snapshot is observed state:
 * every value in it is a value the account actually has. So `unknownAttributes`
 * is always empty here, and a snapshot can legitimately produce a Fail where
 * the equivalent plan produced a not-applicable. That is not an inconsistency
 * between the lanes; it is the snapshot knowing something the plan could not.
 *
 * Read-only by construction, exactly as the Terraform adapter is: this takes
 * the document as a string. Nothing in this file can reach the filesystem, a
 * process, or AWS — producing the snapshot is a documented step the operator
 * runs with their own read-only credentials (see `docs/adr/0004-snapshot-lane.md`
 * and the SECURITY.md posture).
 */
import { compareStrings } from "../util/compare.js";
import type { Resource } from "../model/resource.js";
import { IngestError } from "./errors.js";
import { asArray, asString, isRecord } from "./json.js";
import type { IngestResult } from "./terraform-plan.js";

/** The marker that identifies a document as a snapshot, and its format version. */
export const SNAPSHOT_MARKER = "ccmScannerSnapshot";
const SUPPORTED_VERSION = "1";

/** True when the document is a snapshot rather than Terraform output. */
export function looksLikeSnapshot(parsed: unknown): boolean {
  return isRecord(parsed) && SNAPSHOT_MARKER in parsed;
}

/** `aws_s3_bucket.logs` → provider `aws`. */
function providerOf(type: string): string {
  const [prefix] = type.split("_", 1);
  return prefix === undefined || prefix === "" ? "unknown" : prefix;
}

function readResource(
  entry: unknown,
  index: number,
  seen: Set<string>,
  warnings: string[],
): Resource | undefined {
  const where = `resources[${String(index)}]`;
  if (!isRecord(entry)) {
    warnings.push(`${where} is not an object; skipped`);
    return undefined;
  }

  const address = asString(entry.address);
  const type = asString(entry.type);
  if (address === undefined || address === "") {
    warnings.push(`${where} has no "address"; skipped`);
    return undefined;
  }
  if (type === undefined || type === "") {
    warnings.push(`${where} ("${address}") has no "type"; skipped`);
    return undefined;
  }
  // A duplicate address would let one resource's verdict silently replace
  // another's, so it is reported rather than resolved by guessing.
  if (seen.has(address)) {
    warnings.push(`duplicate address "${address}" at ${where}; the later one is skipped`);
    return undefined;
  }
  seen.add(address);

  const attributes = isRecord(entry.attributes) ? entry.attributes : undefined;
  if (attributes === undefined) {
    warnings.push(`${where} ("${address}") has no "attributes" object; treated as empty`);
  }

  const sensitive = asArray(entry.sensitiveAttributes).flatMap((name) => {
    const text = asString(name);
    return text === undefined || text === "" ? [] : [text];
  });

  return {
    address,
    type,
    // Terraform addresses are `type.name`; anything else keeps the address.
    name: address.split(".").pop() ?? address,
    provider: asString(entry.provider) ?? providerOf(type),
    attributes: attributes ?? {},
    // Observed state, so nothing is pending: see the note at the top.
    unknownAttributes: [],
    sensitiveAttributes: sensitive,
  };
}

export function ingestSnapshot(raw: string, source: string): IngestResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new IngestError(source, "input is not valid JSON");
  }
  if (!isRecord(parsed)) {
    throw new IngestError(source, "expected a JSON object at the document root");
  }

  const version = asString(parsed[SNAPSHOT_MARKER]);
  if (version === undefined) {
    throw new IngestError(
      source,
      `no "${SNAPSHOT_MARKER}" version marker — is this a ccm-scanner snapshot?`,
    );
  }
  if (version !== SUPPORTED_VERSION) {
    throw new IngestError(
      source,
      `snapshot format "${version}" is not supported (this build reads "${SUPPORTED_VERSION}")`,
    );
  }

  const warnings: string[] = [];
  const rawResources = parsed.resources;
  if (!Array.isArray(rawResources)) {
    throw new IngestError(source, '"resources" must be an array');
  }

  const seen = new Set<string>();
  const resources = rawResources.flatMap((entry, index) => {
    const resource = readResource(entry, index, seen, warnings);
    return resource === undefined ? [] : [resource];
  });

  if (resources.length === 0) {
    warnings.push("no resources found in the snapshot");
  }

  // Sorted by address, as the Terraform adapter does, so the report never
  // depends on the order the producer happened to emit.
  resources.sort((a, b) => compareStrings(a.address, b.address));

  return { model: { source, resources }, warnings };
}
