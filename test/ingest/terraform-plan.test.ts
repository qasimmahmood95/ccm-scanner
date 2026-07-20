import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { IngestError, ingestTerraformPlan } from "../../src/ingest/index.js";

function fixture(name: string): string {
  return readFileSync(new URL(`../../fixtures/${name}`, import.meta.url), "utf8");
}

const compliant = ingestTerraformPlan(fixture("compliant/terraform-plan.json"), "compliant");

describe("ingestTerraformPlan", () => {
  it("collects managed resources from the root module and child modules", () => {
    expect(compliant.model.resources.map((resource) => resource.address)).toEqual([
      "aws_iam_account_password_policy.strict",
      "aws_kms_key.logs",
      "aws_security_group.web",
      "module.storage.aws_s3_bucket.logs",
      "module.storage.aws_s3_bucket_public_access_block.logs",
    ]);
  });

  it("sorts by address so the model does not depend on Terraform's emit order", () => {
    const addresses = compliant.model.resources.map((resource) => resource.address);
    expect([...addresses].sort()).toEqual(addresses);
  });

  it("skips data sources, which are lookups rather than infrastructure", () => {
    expect(compliant.model.resources.some((resource) => resource.address.startsWith("data."))).toBe(
      false,
    );
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
  });

  it("is deterministic for the same input", () => {
    const again = ingestTerraformPlan(fixture("compliant/terraform-plan.json"), "compliant");
    expect(again.model).toEqual(compliant.model);
  });

  it("ingests the non-compliant fixture too", () => {
    const result = ingestTerraformPlan(fixture("non-compliant/terraform-plan.json"), "bad");
    expect(result.model.resources.map((resource) => resource.address)).toContain(
      "aws_security_group.admin",
    );
    expect(result.warnings).toEqual([]);
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
    const result = ingestTerraformPlan(raw, "state");
    expect(result.model.resources).toHaveLength(1);
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
});

describe("malformed input", () => {
  it("rejects non-JSON", () => {
    expect(() => ingestTerraformPlan("not json", "x")).toThrow(IngestError);
  });

  it("rejects a JSON array at the root", () => {
    expect(() => ingestTerraformPlan("[]", "x")).toThrow(/expected a JSON object/);
  });

  it("rejects a document with neither planned_values nor values", () => {
    expect(() => ingestTerraformPlan(JSON.stringify({ format_version: "1.2" }), "x")).toThrow(
      /planned_values/,
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

  it("warns when there are no managed resources", () => {
    const raw = JSON.stringify({ planned_values: { root_module: { resources: [] } } });
    expect(ingestTerraformPlan(raw, "x").warnings).toContain(
      "no managed resources found in the input",
    );
  });
});
