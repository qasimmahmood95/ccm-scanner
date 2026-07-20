/**
 * Parsing and validating the CLI's arguments, separately from acting on them.
 *
 * Everything here is pure and total: it either returns a settled set of options
 * or throws a `UsageError` naming what was wrong and what was expected. A
 * mistyped selector must never quietly narrow a scan — a report that silently
 * assessed three controls instead of thirteen still says "PASS".
 */
import { INPUT_FORMATS, type InputFormat } from "../ingest/index.js";
import { CCM_DOMAINS, isCcmDomain, type CcmDomain } from "../model/ccm.js";

/** Thrown for bad input from the user, as distinct from a bug in the scanner. */
export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

export type OutputFormat = "json" | "md" | "both";
export type FailOn = "fail" | "none";

/** `all`, or an explicit union of domains and individual controls. */
export type ControlSelection =
  | { readonly kind: "all" }
  | {
      readonly kind: "some";
      readonly domains: readonly CcmDomain[];
      readonly ccmIds: readonly string[];
    };

export interface ScanOptions {
  readonly controls: ControlSelection;
  readonly format: OutputFormat;
  readonly failOn: FailOn;
  /** Directory for the evidence pack. Absent means write to stdout. */
  readonly out: string | undefined;
  /** Absent means detect it from the document. */
  readonly inputFormat: InputFormat | undefined;
}

/**
 * An explicit override for the format sniff.
 *
 * Detection handles both shipped formats, so this exists for the case where a
 * document is ambiguous or the sniff is wrong — not as something a user should
 * normally have to think about.
 */
export function parseInputFormat(value: string): InputFormat {
  const match = INPUT_FORMATS.find((format) => format === value);
  if (match === undefined) {
    throw new UsageError(
      `--input-format must be one of ${INPUT_FORMATS.join(", ")} (got "${value}").`,
    );
  }
  return match;
}

const CCM_ID_PATTERN = /^[A-Za-z]{2,4}-\d{1,3}$/;

/**
 * A comma-separated list of domains and/or CCM control ids, or `all`.
 *
 * The list reads as a union — `--controls iam,CEK-12` means the IAM domain
 * *plus* CEK-12, which is what a comma means to everyone who is not a database.
 */
export function parseControls(value: string): ControlSelection {
  const tokens = value
    .split(",")
    .map((token) => token.trim())
    .filter((token) => token !== "");

  if (tokens.length === 0) {
    throw new UsageError(
      "--controls was empty. Pass `all`, one or more domains " +
        `(${CCM_DOMAINS.map((domain) => domain.toLowerCase()).join(", ")}), ` +
        "or CCM control ids such as IAM-05.",
    );
  }

  if (tokens.some((token) => token.toLowerCase() === "all")) {
    if (tokens.length > 1) {
      throw new UsageError(
        "--controls cannot combine `all` with other selectors: `all` already " +
          "selects everything, so the rest would be silently ignored.",
      );
    }
    return { kind: "all" };
  }

  const domains: CcmDomain[] = [];
  const ccmIds: string[] = [];
  const unrecognised: string[] = [];

  for (const token of tokens) {
    const upper = token.toUpperCase();
    if (isCcmDomain(upper)) {
      domains.push(upper);
    } else if (CCM_ID_PATTERN.test(token)) {
      ccmIds.push(upper);
    } else {
      unrecognised.push(token);
    }
  }

  if (unrecognised.length > 0) {
    throw new UsageError(
      `--controls does not recognise: ${unrecognised.join(", ")}. Expected \`all\`, a domain ` +
        `(${CCM_DOMAINS.map((domain) => domain.toLowerCase()).join(", ")}), ` +
        "or a CCM control id such as IAM-05.",
    );
  }

  return { kind: "some", domains, ccmIds };
}

export function parseFormat(value: string): OutputFormat {
  if (value === "json" || value === "md" || value === "both") {
    return value;
  }
  throw new UsageError(`--format must be json, md or both (got "${value}").`);
}

export function parseFailOn(value: string): FailOn {
  if (value === "fail" || value === "none") {
    return value;
  }
  throw new UsageError(`--fail-on must be fail or none (got "${value}").`);
}

/**
 * Rejects the one combination with no sensible meaning.
 *
 * Two documents cannot share one stdout without a delimiter that would corrupt
 * both, and inventing one would make the JSON unparseable — so this is a usage
 * error rather than a guess.
 */
export function validateDestination(format: OutputFormat, out: string | undefined): void {
  // A blank --out is almost always an unset shell variable. Resolving it would
  // silently drop the evidence pack into the current directory — and would slip
  // past the `both` check below, defeating the one combination it exists for.
  if (out !== undefined && out.trim() === "") {
    throw new UsageError(
      "--out was empty. Give a directory, or omit --out to write to stdout. " +
        "(An empty value is usually an unset shell variable.)",
    );
  }
  if (format === "both" && out === undefined) {
    throw new UsageError(
      "--format both writes two documents, so it needs --out <dir>. Use --format json " +
        "or --format md to write a single document to stdout.",
    );
  }
}
