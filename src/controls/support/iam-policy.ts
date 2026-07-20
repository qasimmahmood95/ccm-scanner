/**
 * Parsing for AWS IAM policy documents.
 *
 * Terraform carries policy documents as embedded JSON strings, and every field
 * that can be a string can also be a list. We normalise that here so checks
 * stay readable.
 *
 * The parse result distinguishes three outcomes rather than collapsing them:
 * a document we understood, one that is syntactically fine but declares no
 * statements, and one we could not read. Only the last is a reason to say the
 * control cannot be evidenced.
 */
import { asArray, asString, isRecord } from "../../ingest/json.js";

export type Effect = "Allow" | "Deny";

export interface PolicyCondition {
  /** Lowercased operator, e.g. `bool`, `boolifexists`, `stringequals`. */
  readonly operator: string;
  /** Lowercased condition key, e.g. `aws:securetransport`. */
  readonly key: string;
  /** Lowercased values. */
  readonly values: readonly string[];
}

export interface PolicyStatement {
  readonly effect: Effect;
  readonly actions: readonly string[];
  readonly resources: readonly string[];
  /**
   * Inverted matchers. A statement using these grants or denies everything
   * *except* what it lists, which no simple predicate over `actions` /
   * `resources` can evaluate — checks must decline rather than guess.
   */
  readonly notActions: readonly string[];
  readonly notResources: readonly string[];
  /** Flattened principals, e.g. `*`, `arn:aws:iam::123456789012:root`. */
  readonly principals: readonly string[];
  readonly conditions: readonly PolicyCondition[];
  readonly hasCondition: boolean;
  /** Condition keys, lowercased — convenience over `conditions`. */
  readonly conditionKeys: readonly string[];
}

export type PolicyParse =
  | { readonly kind: "statements"; readonly statements: readonly PolicyStatement[] }
  /** Valid JSON, but no statements to evaluate. */
  | { readonly kind: "empty" }
  /** Absent, not JSON, or not shaped like a policy document. */
  | { readonly kind: "unparseable" };

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

function collectConditions(condition: unknown): readonly PolicyCondition[] {
  if (!isRecord(condition)) {
    return [];
  }
  // { "Bool": { "aws:SecureTransport": "false" } }
  return Object.entries(condition).flatMap(([operator, operands]) => {
    if (!isRecord(operands)) {
      return [];
    }
    return Object.entries(operands).map(([key, values]) => ({
      operator: operator.toLowerCase(),
      key: key.toLowerCase(),
      values: toStringList(values).map((value) => value.toLowerCase()),
    }));
  });
}

/** Case-insensitive, because the surrounding keys are accepted case-insensitively too. */
function normaliseEffect(value: unknown): Effect {
  return (asString(value) ?? "Allow").toLowerCase() === "deny" ? "Deny" : "Allow";
}

function toStatement(raw: unknown): PolicyStatement | undefined {
  if (!isRecord(raw)) {
    return undefined;
  }
  const conditions = collectConditions(raw.Condition ?? raw.condition);
  return {
    effect: normaliseEffect(raw.Effect ?? raw.effect),
    actions: toStringList(raw.Action ?? raw.action),
    resources: toStringList(raw.Resource ?? raw.resource),
    notActions: toStringList(raw.NotAction ?? raw.notAction),
    notResources: toStringList(raw.NotResource ?? raw.notResource),
    principals: collectPrincipals(raw.Principal ?? raw.principal),
    conditions,
    hasCondition: conditions.length > 0,
    conditionKeys: conditions.map((condition) => condition.key),
  };
}

/**
 * Parses a policy document from a Terraform attribute, which may be a JSON
 * string or an already-decoded object.
 */
export function parsePolicyDocument(value: unknown): PolicyParse {
  let document: unknown = value;

  const asJsonString = asString(value);
  if (asJsonString !== undefined) {
    try {
      document = JSON.parse(asJsonString);
    } catch {
      return { kind: "unparseable" };
    }
  }

  if (!isRecord(document)) {
    return { kind: "unparseable" };
  }

  const rawStatements = document.Statement ?? document.statement;
  if (rawStatements === undefined) {
    return { kind: "unparseable" };
  }

  const list = Array.isArray(rawStatements) ? rawStatements : [rawStatements];
  const statements = list.flatMap((entry) => {
    const statement = toStatement(entry);
    return statement === undefined ? [] : [statement];
  });

  return statements.length > 0 ? { kind: "statements", statements } : { kind: "empty" };
}

/** True when a principal entry grants everyone, e.g. `*` or `arn:aws:iam::*:root`. */
export function isWildcardPrincipal(principal: string): boolean {
  return principal === "*" || principal.includes("::*:");
}

/**
 * Condition keys that actually narrow *who* may act. Any other condition on a
 * wildcard-principal Allow constrains something else entirely (transport,
 * region, time) and leaves the principal wide open.
 */
const PRINCIPAL_CONSTRAINING_KEYS = new Set([
  "aws:principalarn",
  "aws:principalorgid",
  "aws:principalorgpaths",
  "aws:principalaccount",
  "aws:principaltag",
  "aws:principalistype",
  "aws:sourcearn",
  "aws:sourceaccount",
  "aws:sourceowner",
  "aws:sourcevpc",
  "aws:sourcevpce",
  "aws:sourceip",
  "sts:externalid",
]);

export function constrainsPrincipal(statement: PolicyStatement): boolean {
  return statement.conditions.some(
    (condition) =>
      PRINCIPAL_CONSTRAINING_KEYS.has(condition.key) ||
      condition.key.startsWith("aws:principaltag/"),
  );
}

/** True when the statement uses an inverted matcher we cannot evaluate. */
export function usesInvertedMatch(statement: PolicyStatement): boolean {
  return statement.notActions.length > 0 || statement.notResources.length > 0;
}
