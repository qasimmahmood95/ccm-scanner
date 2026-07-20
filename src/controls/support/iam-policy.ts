/**
 * Parsing for AWS IAM policy documents.
 *
 * Terraform carries policy documents as embedded JSON strings, and every field
 * that can be a string can also be a list. We normalise that here so checks
 * stay readable. If a document cannot be parsed we return `undefined` rather
 * than guessing — the caller then reports Not-Applicable with a reason.
 */
import { asArray, asString, isRecord } from "../../ingest/json.js";

export interface PolicyStatement {
  readonly effect: string;
  readonly actions: readonly string[];
  readonly resources: readonly string[];
  /** Flattened principals, e.g. `*`, `arn:aws:iam::123456789012:root`. */
  readonly principals: readonly string[];
  readonly hasCondition: boolean;
  /** Condition keys, lowercased, e.g. `aws:multifactorauthpresent`. */
  readonly conditionKeys: readonly string[];
}

/** Accepts a string, a list of strings, or absent. */
function toStringList(value: unknown): readonly string[] {
  const single = asString(value);
  if (single !== undefined) {
    return [single];
  }
  return asArray(value).flatMap((entry) => {
    const item = asString(entry);
    return item === undefined ? [] : [item];
  });
}

function collectPrincipals(value: unknown): readonly string[] {
  const direct = toStringList(value);
  if (direct.length > 0) {
    return direct;
  }
  if (!isRecord(value)) {
    return [];
  }
  // { "AWS": "*" } / { "Service": ["ec2.amazonaws.com"] }
  return Object.values(value).flatMap((entry) => toStringList(entry));
}

function collectConditionKeys(condition: unknown): readonly string[] {
  if (!isRecord(condition)) {
    return [];
  }
  // { "Bool": { "aws:MultiFactorAuthPresent": "true" } }
  return Object.values(condition).flatMap((operands) =>
    isRecord(operands) ? Object.keys(operands).map((key) => key.toLowerCase()) : [],
  );
}

function toStatement(raw: unknown): PolicyStatement | undefined {
  if (!isRecord(raw)) {
    return undefined;
  }
  const condition = raw.Condition ?? raw.condition;
  return {
    effect: asString(raw.Effect ?? raw.effect) ?? "Allow",
    actions: toStringList(raw.Action ?? raw.action),
    resources: toStringList(raw.Resource ?? raw.resource),
    principals: collectPrincipals(raw.Principal ?? raw.principal),
    hasCondition: isRecord(condition) && Object.keys(condition).length > 0,
    conditionKeys: collectConditionKeys(condition),
  };
}

/**
 * Parses a policy document from a Terraform attribute, which may be a JSON
 * string or an already-decoded object. Returns `undefined` when the value is
 * absent or cannot be understood.
 */
export function parsePolicyDocument(value: unknown): readonly PolicyStatement[] | undefined {
  let document: unknown = value;

  const asJsonString = asString(value);
  if (asJsonString !== undefined) {
    try {
      document = JSON.parse(asJsonString);
    } catch {
      return undefined;
    }
  }

  if (!isRecord(document)) {
    return undefined;
  }

  const rawStatements = document.Statement ?? document.statement;
  if (rawStatements === undefined) {
    return undefined;
  }

  const list = Array.isArray(rawStatements) ? rawStatements : [rawStatements];
  const statements = list.flatMap((entry) => {
    const statement = toStatement(entry);
    return statement === undefined ? [] : [statement];
  });

  return statements.length > 0 ? statements : undefined;
}

/** True when the list contains a bare `*`. */
export function hasWildcard(values: readonly string[]): boolean {
  return values.includes("*");
}

/** True when a principal entry grants everyone, e.g. `*` or `arn:aws:iam::*:root`. */
export function isWildcardPrincipal(principal: string): boolean {
  return principal === "*" || principal.includes("::*:");
}
