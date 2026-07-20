import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { IngestError, ingestTerraformPlan } from "../../src/ingest/index.js";
import { isUnknown } from "../../src/model/index.js";

function fixture(name: string): string {
  return readFileSync(new URL(`../../fixtures/${name}`, import.meta.url), "utf8");
}

const compliant = ingestTerraformPlan(fixture("compliant/terraform-plan.json"), "compliant");
const nonCompliant = ingestTerraformPlan(fixture("non-compliant/terraform-plan.json"), "bad");

function addressesOf(result: typeof compliant): string[] {
  return result.model.resources.map((resource) => resource.address);
}

describe("ingestTerraformPlan", () => {
  it("collects managed resources from the root module and nested child modules", () => {
    expect(addressesOf(compliant)).toEqual([
      "aws_iam_account_password_policy.strict",
      "aws_kms_key.logs",
      "aws_security_group.web",
      'module.storage.aws_s3_bucket.logs["primary"]',
      "module.storage.aws_s3_bucket_public_access_block.logs",
      "module.storage.module.replica.aws_s3_bucket.archive",
    ]);
  });

  it("skips data sources, which are lookups rather than infrastructure", () => {
    // The fixture really does contain one, so this cannot pass vacuously.
    expect(fixture("compliant/terraform-plan.json")).toContain('"mode": "data"');
    expect(addressesOf(compliant).some((address) => address.startsWith("data."))).toBe(false);
  });

  it("derives the short provider name", () => {
    expect(new Set(compliant.model.resources.map((resource) => resource.provider))).toEqual(
      new Set(["aws"]),
    );
  });

  it("preserves attributes verbatim", () => {
    const key = compliant.model.resources.find(
      (resource) => resource.address === "aws_kms_key.logs",
    );
    expect(key?.attributes.enable_key_rotation).toBe(true);
  });

  it("records the source label and reports no warnings for a clean input", () => {
    expect(compliant.model.source).toBe("compliant");
    expect(compliant.warnings).toEqual([]);
    expect(nonCompliant.warnings).toEqual([]);
  });

  // toEqual is order-insensitive for object keys, so it cannot detect the
  // byte-level instability this project actually cares about.
  it("is byte-for-byte deterministic for the same input", () => {
    const again = ingestTerraformPlan(fixture("compliant/terraform-plan.json"), "compliant");
    expect(JSON.stringify(again.model)).toBe(JSON.stringify(compliant.model));
  });

  it("sorts by code unit, not by locale", () => {
    // These orders differ between code-unit and locale comparison, so the test
    // fails if sorting ever becomes locale-sensitive.
    const raw = JSON.stringify({
      planned_values: {
        root_module: {
          resources: ["ab", "Zeta", "a_b", "alpha"].map((name) => ({
            address: name,
            mode: "managed",
            type: "aws_kms_key",
            name,
            provider_name: "registry.terraform.io/hashicorp/aws",
            values: {},
          })),
        },
      },
    });
    expect(addressesOf(ingestTerraformPlan(raw, "x"))).toEqual(["Zeta", "a_b", "ab", "alpha"]);
  });
});

// A plan writes unknown-until-apply values as null, indistinguishable from
// "not configured". Only resource_changes[].change.after_unknown separates
// them, and ingest is the only layer that can see it.
describe("values that are not known until apply", () => {
  it("records which attributes are unknown", () => {
    const volume = nonCompliant.model.resources.find(
      (resource) => resource.address === "aws_ebs_volume.data",
    );
    expect(volume?.unknownAttributes).toEqual(["arn", "encrypted", "id", "kms_key_id"]);
  });

  it("exposes them through isUnknown, so a check can report not-applicable", () => {
    const volume = nonCompliant.model.resources.find(
      (resource) => resource.address === "aws_ebs_volume.data",
    );
    if (volume === undefined) {
      throw new Error("fixture should contain aws_ebs_volume.data");
    }
    // The attribute is present and null: without the unknown list a check
    // would read it as "not configured" and guess.
    expect(volume.attributes.encrypted).toBeNull();
    expect(isUnknown(volume, "encrypted")).toBe(true);
    expect(isUnknown(volume, "size")).toBe(false);
  });

  it("treats a partially-unknown block as unknown", () => {
    const key = compliant.model.resources.find(
      (resource) => resource.address === "aws_kms_key.logs",
    );
    expect(key?.unknownAttributes).toEqual(["arn", "key_id", "policy"]);
  });

  it("does not mark an attribute whose after_unknown subtree has no true leaf", () => {
    const group = compliant.model.resources.find(
      (resource) => resource.address === "aws_security_group.web",
    );
    expect(group?.unknownAttributes).toEqual(["arn", "id"]);
  });

  it("leaves the list empty for state output, which has no resource_changes", () => {
    const raw = JSON.stringify({
      values: {
        root_module: {
          resources: [
            {
              address: "aws_kms_key.k",
              mode: "managed",
              type: "aws_kms_key",
              name: "k",
              provider_name: "registry.terraform.io/hashicorp/aws",
              values: { enable_key_rotation: true },
            },
          ],
        },
      },
    });
    expect(ingestTerraformPlan(raw, "state").model.resources[0]?.unknownAttributes).toEqual([]);
  });
});

// show -json of state puts real secrets in values, and the report is an
// artifact people commit and share.
describe("sensitive attributes", () => {
  it("records which attributes Terraform marks sensitive", () => {
    const db = nonCompliant.model.resources.find(
      (resource) => resource.address === "module.storage.aws_db_instance.main",
    );
    expect(db?.sensitiveAttributes).toEqual(["password"]);
  });

  it("is empty when nothing is marked", () => {
    const key = compliant.model.resources.find(
      (resource) => resource.address === "aws_kms_key.logs",
    );
    expect(key?.sensitiveAttributes).toEqual([]);
  });
});

describe("terraform state (`show -json`) form", () => {
  it("reads resources from `values` when there is no plan", () => {
    const raw = JSON.stringify({
      values: {
        root_module: {
          resources: [
            {
              address: "aws_kms_key.k",
              mode: "managed",
              type: "aws_kms_key",
              name: "k",
              provider_name: "registry.terraform.io/hashicorp/aws",
              values: { enable_key_rotation: true },
            },
          ],
        },
      },
    });
    expect(ingestTerraformPlan(raw, "state").model.resources).toHaveLength(1);
  });

  it("prefers planned_values and warns when both are present", () => {
    const raw = JSON.stringify({
      planned_values: { root_module: { resources: [] } },
      values: { root_module: { resources: [] } },
    });
    expect(ingestTerraformPlan(raw, "both").warnings).toContain(
      'input contains both "planned_values" and "values"; using "planned_values"',
    );
  });

  it("returns an empty model, not an error, for Terraform output with nothing to audit", () => {
    const result = ingestTerraformPlan(
      JSON.stringify({ format_version: "1.2", terraform_version: "1.9.8" }),
      "empty",
    );
    expect(result.model.resources).toEqual([]);
    expect(result.warnings).toContain(
      'input has no "planned_values" or "values" — nothing to audit',
    );
  });
});

describe("provider names", () => {
  function providerFor(providerName: unknown): string | undefined {
    const raw = JSON.stringify({
      planned_values: {
        root_module: {
          resources: [
            { address: "a.b", mode: "managed", type: "a", name: "b", provider_name: providerName },
          ],
        },
      },
    });
    return ingestTerraformPlan(raw, "x").model.resources[0]?.provider;
  }

  it("takes the last segment", () => {
    expect(providerFor("registry.terraform.io/hashicorp/aws")).toBe("aws");
  });

  it("accepts a bare name", () => {
    expect(providerFor("aws")).toBe("aws");
  });

  it("falls back to unknown for a trailing slash or a missing name", () => {
    expect(providerFor("registry.terraform.io/hashicorp/")).toBe("unknown");
    expect(providerFor(undefined)).toBe("unknown");
  });
});

describe("malformed input", () => {
  it("rejects non-JSON", () => {
    expect(() => ingestTerraformPlan("not json", "x")).toThrow(IngestError);
  });

  // `terraform plan -json` is a newline-delimited log stream, not a plan
  // representation, and the docs used to claim we accepted it.
  it("explains what to run when handed a plan -json log stream", () => {
    const ndjson =
      '{"@level":"info","@message":"Terraform 1.9.8","@module":"terraform.ui"}\n' +
      '{"@level":"info","@message":"aws_kms_key.k: Plan to create","type":"planned_change"}\n';
    expect(() => ingestTerraformPlan(ndjson, "x")).toThrow(/terraform show -json tfplan/);
  });

  it("rejects a JSON array at the root", () => {
    expect(() => ingestTerraformPlan("[]", "x")).toThrow(/expected a JSON object/);
  });

  it("rejects a document with no Terraform marker at all", () => {
    expect(() => ingestTerraformPlan(JSON.stringify({ hello: "world" }), "x")).toThrow(
      /is this `terraform show -json` output\?/,
    );
  });

  it("warns rather than throws when a resource entry is unusable", () => {
    const raw = JSON.stringify({
      planned_values: {
        root_module: {
          resources: [{ mode: "managed", type: "aws_kms_key" }, "nonsense"],
        },
      },
    });
    const result = ingestTerraformPlan(raw, "x");
    expect(result.model.resources).toEqual([]);
    expect(result.warnings).toContain("skipped a managed resource missing address, type or name");
    expect(result.warnings).toContain("skipped a resource entry that was not an object");
  });

  // Silently dropping a subtree is the worst outcome: the caller sees an empty
  // warning list and a model that looks complete.
  it("warns when a child module is not an object", () => {
    const raw = JSON.stringify({
      planned_values: { root_module: { resources: [], child_modules: [null, "oops"] } },
    });
    const warnings = ingestTerraformPlan(raw, "x").warnings;
    expect(warnings).toContain("skipped root_module.child_modules[0], which was not an object");
    expect(warnings).toContain("skipped root_module.child_modules[1], which was not an object");
  });

  it("warns when resources is present but not an array", () => {
    const raw = JSON.stringify({
      planned_values: { root_module: { resources: { "0": { address: "a.b" } } } },
    });
    expect(ingestTerraformPlan(raw, "x").warnings).toContain(
      "skipped root_module.resources, which was not an array",
    );
  });

  it("warns when values is present but not an object", () => {
    const raw = JSON.stringify({
      planned_values: {
        root_module: {
          resources: [{ address: "a.b", mode: "managed", type: "a", name: "b", values: null }],
        },
      },
    });
    expect(ingestTerraformPlan(raw, "x").warnings).toContain(
      'a.b has a non-object "values"; treating it as no attributes',
    );
  });

  it("warns on a duplicate address rather than auditing only the first", () => {
    const entry = {
      address: "aws_kms_key.k",
      mode: "managed",
      type: "aws_kms_key",
      name: "k",
      values: {},
    };
    const raw = JSON.stringify({
      planned_values: { root_module: { resources: [entry, entry] } },
    });
    const result = ingestTerraformPlan(raw, "x");
    expect(result.model.resources).toHaveLength(1);
    expect(result.warnings).toContain("skipped a duplicate resource address: aws_kms_key.k");
  });

  it("warns when there are no managed resources", () => {
    const raw = JSON.stringify({ planned_values: { root_module: { resources: [] } } });
    expect(ingestTerraformPlan(raw, "x").warnings).toContain(
      "no managed resources found in the input",
    );
  });
});
