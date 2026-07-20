import type { Check } from "../../engine/check.js";
import { resourcesOfType, type Resource, type ResourceModel } from "../../model/resource.js";
import { fail, notApplicable, pass, type Evidence, type Finding } from "../../model/verdict.js";
import { asNumber, readAttribute, unknownReason } from "../support/attributes.js";
import {
  constrainsPrincipal,
  isWildcardPrincipal,
  parsePolicyDocument,
  usesInvertedMatch,
  type PolicyStatement,
} from "../support/iam-policy.js";

/** Terraform resource types that carry an inline or managed policy document. */
const POLICY_TYPES = [
  "aws_iam_policy",
  "aws_iam_role_policy",
  "aws_iam_user_policy",
  "aws_iam_group_policy",
] as const;

const PASSWORD_POLICY_TYPE = "aws_iam_account_password_policy";

function policyBearingResources(model: ResourceModel): readonly Resource[] {
  return POLICY_TYPES.flatMap((type) => resourcesOfType(model, type));
}

/**
 * Reads a policy document attribute, mapping every non-evaluable outcome to a
 * not-applicable finding with a reason that says which one it was.
 */
function withStatements(
  resource: Resource,
  attribute: string,
  evaluate: (statements: readonly PolicyStatement[]) => Finding,
): Finding {
  const read = readAttribute(resource, attribute);
  if (read.kind === "unknown") {
    return notApplicable(unknownReason(resource, attribute));
  }
  if (read.kind === "absent") {
    return notApplicable(`${resource.address} declares no ${attribute} to inspect.`);
  }

  const parsed = parsePolicyDocument(read.value);
  if (parsed.kind === "unparseable") {
    return notApplicable(
      `The ${attribute} on ${resource.address} could not be parsed, so its contents ` +
        `cannot be evidenced.`,
    );
  }
  if (parsed.kind === "empty") {
    return notApplicable(`The ${attribute} on ${resource.address} declares no statements.`);
  }
  return evaluate(parsed.statements);
}

/**
 * IAM-05 — Least Privilege.
 *
 * Fails a policy that pairs a wildcard action with a wildcard resource in a
 * single Allow. A statement using NotAction/NotResource grants everything
 * *except* what it lists; no predicate over `actions`/`resources` can evaluate
 * that, so we decline rather than report a Pass we cannot support.
 */
const noWildcardAllow: Check = {
  checkId: "iam/no-wildcard-allow",
  ccmId: "IAM-05",
  ccmTitle: "Least Privilege",
  run: (model) => {
    const policies = policyBearingResources(model);
    if (policies.length === 0) {
      return [
        notApplicable(
          "No IAM policy documents are declared in this input, so least privilege cannot be evidenced from it.",
        ),
      ];
    }

    return policies.map((resource): Finding =>
      withStatements(resource, "policy", (statements) => {
        const allows = statements.filter((statement) => statement.effect === "Allow");

        const inverted = allows.filter(usesInvertedMatch);
        if (inverted.length > 0) {
          return notApplicable(
            `${resource.address} uses NotAction or NotResource, which grants everything ` +
              `except what it lists. Its effective permissions cannot be evidenced by this check.`,
          );
        }

        const offending = allows.filter(
          (statement) => statement.actions.includes("*") && statement.resources.includes("*"),
        );

        const evidence: Evidence[] = [
          {
            resourceAddress: resource.address,
            attribute: "policy",
            observed:
              offending.length > 0
                ? offending.map((statement) => ({
                    Effect: statement.effect,
                    Action: statement.actions,
                    Resource: statement.resources,
                  }))
                : `${String(statements.length)} statement(s), none granting *:*`,
            expected: "no Allow statement pairing a wildcard action with a wildcard resource",
          },
        ];

        return offending.length > 0 ? fail(evidence) : pass(evidence);
      }),
    );
  },
};

/**
 * IAM-16 — Authorization Mechanisms.
 *
 * A role anyone may assume is an authorization failure regardless of what the
 * role can then do. A wildcard principal is acceptable only when a condition
 * narrows *who* — `aws:PrincipalOrgID`, `sts:ExternalId` and friends. A
 * condition on something else entirely (transport, region) leaves the
 * principal wide open, so we neither pass nor fail it: we say we cannot tell.
 */
const noWildcardTrust: Check = {
  checkId: "iam/no-wildcard-trust",
  ccmId: "IAM-16",
  ccmTitle: "Authorization Mechanisms",
  run: (model) => {
    const roles = resourcesOfType(model, "aws_iam_role");
    if (roles.length === 0) {
      return [notApplicable("No IAM roles are declared in this input.")];
    }

    return roles.map((resource): Finding =>
      withStatements(resource, "assume_role_policy", (statements) => {
        const wildcardAllows = statements.filter(
          (statement) =>
            statement.effect === "Allow" && statement.principals.some(isWildcardPrincipal),
        );

        const unconditioned = wildcardAllows.filter((statement) => !statement.hasCondition);
        if (unconditioned.length > 0) {
          return fail([
            {
              resourceAddress: resource.address,
              attribute: "assume_role_policy",
              observed: unconditioned.map((statement) => ({ Principal: statement.principals })),
              expected: "no unconditioned Allow for a wildcard principal",
            },
          ]);
        }

        const ambiguous = wildcardAllows.filter((statement) => !constrainsPrincipal(statement));
        if (ambiguous.length > 0) {
          return notApplicable(
            `${resource.address} allows a wildcard principal under conditions that do not ` +
              `narrow who may assume the role (` +
              `${ambiguous.flatMap((statement) => statement.conditionKeys).join(", ")}` +
              `), so whether access is constrained cannot be evidenced.`,
          );
        }

        return pass([
          {
            resourceAddress: resource.address,
            attribute: "assume_role_policy",
            observed: statements.flatMap((statement) => statement.principals),
            expected: "no unconditioned Allow for a wildcard principal",
          },
        ]);
      }),
    );
  },
};

/**
 * Both password checks read one account-level singleton. When the input does
 * not declare it we report not-applicable rather than fail: the account may set
 * it outside this Terraform, and we scan the input, not the account.
 */
function passwordPolicyFindings(
  model: ResourceModel,
  control: string,
  evaluate: (policy: Resource) => Finding,
): readonly Finding[] {
  const policies = resourcesOfType(model, PASSWORD_POLICY_TYPE);
  if (policies.length === 0) {
    return [
      notApplicable(
        `No ${PASSWORD_POLICY_TYPE} is declared in this input, so ${control} cannot be ` +
          `evidenced from it. The account may set one outside this configuration.`,
      ),
    ];
  }
  return policies.map(evaluate);
}

interface Threshold {
  readonly attribute: string;
  readonly satisfied: (value: unknown) => boolean;
  readonly expected: string;
}

function evaluateThresholds(policy: Resource, thresholds: readonly Threshold[]): Finding {
  const evidence: Evidence[] = [];
  const unmet: string[] = [];

  for (const threshold of thresholds) {
    const read = readAttribute(policy, threshold.attribute);
    if (read.kind === "unknown") {
      return notApplicable(unknownReason(policy, threshold.attribute));
    }
    const value = read.kind === "value" ? read.value : undefined;
    if (!threshold.satisfied(value)) {
      unmet.push(threshold.attribute);
    }
    evidence.push({
      resourceAddress: policy.address,
      attribute: threshold.attribute,
      observed: value ?? null,
      expected: threshold.expected,
    });
  }

  return unmet.length > 0 ? fail(evidence) : pass(evidence);
}

function atLeast(minimum: number): (value: unknown) => boolean {
  return (value) => typeof value === "number" && value >= minimum;
}

/** IAM-02 — Strong Password Policy and Procedures. Strength only; lifecycle is IAM-15. */
const accountPasswordPolicy: Check = {
  checkId: "iam/account-password-policy",
  ccmId: "IAM-02",
  ccmTitle: "Strong Password Policy and Procedures",
  run: (model) =>
    passwordPolicyFindings(model, "password strength", (policy) =>
      evaluateThresholds(policy, [
        {
          attribute: "minimum_password_length",
          satisfied: atLeast(14),
          expected: "at least 14 characters",
        },
        {
          attribute: "require_uppercase_characters",
          satisfied: (value) => value === true,
          expected: "true",
        },
        {
          attribute: "require_lowercase_characters",
          satisfied: (value) => value === true,
          expected: "true",
        },
        { attribute: "require_numbers", satisfied: (value) => value === true, expected: "true" },
        { attribute: "require_symbols", satisfied: (value) => value === true, expected: "true" },
      ]),
    ),
};

/** IAM-15 — Passwords Management. Lifecycle: reuse and age. */
const passwordLifecycle: Check = {
  checkId: "iam/password-lifecycle",
  ccmId: "IAM-15",
  ccmTitle: "Passwords Management",
  run: (model) =>
    passwordPolicyFindings(model, "password lifecycle", (policy) =>
      evaluateThresholds(policy, [
        {
          attribute: "password_reuse_prevention",
          satisfied: atLeast(24),
          expected: "at least 24 previous passwords remembered",
        },
        {
          attribute: "max_password_age",
          satisfied: (value) => {
            const age = asNumber({ kind: "value", value });
            return age !== undefined && age > 0 && age <= 90;
          },
          expected: "expiry of 90 days or fewer",
        },
      ]),
    ),
};

/** True when the statement actually *requires* MFA, rather than merely mentioning it. */
function enforcesMfa(statement: PolicyStatement): boolean {
  return statement.conditions.some((condition) => {
    if (condition.key !== "aws:multifactorauthpresent") {
      return false;
    }
    // Deny unless MFA present, or Allow only when MFA present. The inverse of
    // either is a policy that relaxes on MFA, not one that requires it.
    return statement.effect === "Deny"
      ? condition.values.includes("false")
      : condition.values.includes("true");
  });
}

/**
 * IAM-14 — Strong Authentication. Partial coverage by design.
 *
 * Whether a principal has enrolled an MFA device is account runtime state that
 * no Terraform input shows. What is visible is a policy that refuses to
 * authorize without MFA, so we evidence that and say plainly when we cannot.
 */
const mfaEnforcementPresent: Check = {
  checkId: "iam/mfa-enforcement-present",
  ccmId: "IAM-14",
  ccmTitle: "Strong Authentication",
  run: (model) => {
    const enforcing: Evidence[] = [];
    let unreadable = 0;

    for (const resource of policyBearingResources(model)) {
      const read = readAttribute(resource, "policy");
      if (read.kind === "unknown") {
        unreadable += 1;
        continue;
      }
      if (read.kind === "absent") {
        continue;
      }
      const parsed = parsePolicyDocument(read.value);
      if (parsed.kind === "unparseable") {
        unreadable += 1;
        continue;
      }
      if (parsed.kind === "empty") {
        continue;
      }
      if (parsed.statements.some(enforcesMfa)) {
        enforcing.push({
          resourceAddress: resource.address,
          attribute: "policy",
          observed: "requires aws:MultiFactorAuthPresent",
          expected: "privileged access conditioned on MFA",
        });
      }
    }

    if (enforcing.length > 0) {
      return [pass(enforcing)];
    }

    // The reason must not claim more than we looked at.
    const caveat =
      unreadable > 0
        ? ` ${String(unreadable)} policy document(s) could not be read, so this is not exhaustive.`
        : "";
    return [
      notApplicable(
        "No policy in this input requires aws:MultiFactorAuthPresent, and per-principal MFA " +
          "enrolment is account runtime state that declarative infrastructure cannot show." +
          caveat,
      ),
    ];
  },
};

/** IAM-03 — Identity Inventory. Not evidenceable from IaC. */
const identityInventory: Check = {
  checkId: "iam/na-runtime-inventory",
  ccmId: "IAM-03",
  ccmTitle: "Identity Inventory",
  run: () => [
    notApplicable(
      "A complete identity inventory requires enumerating the live account's principals. " +
        "An IaC module is not authoritative for identities created outside it. Becomes " +
        "checkable in the cloud-snapshot lane.",
    ),
  ],
};

/** IAM-08 — User Access Review. A process control with no declarative signal. */
const userAccessReview: Check = {
  checkId: "iam/na-process-control",
  ccmId: "IAM-08",
  ccmTitle: "User Access Review",
  run: () => [
    notApplicable(
      "Periodic access review is a temporal, process control. Declarative infrastructure " +
        "carries no signal of whether or when a review happened.",
    ),
  ],
};

export const iamChecks: readonly Check[] = [
  accountPasswordPolicy,
  identityInventory,
  noWildcardAllow,
  mfaEnforcementPresent,
  passwordLifecycle,
  noWildcardTrust,
  userAccessReview,
];
