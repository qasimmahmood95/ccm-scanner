import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { ScanOptions } from "../../src/cli/options.js";
import { runScan, type ScanResult } from "../../src/cli/run.js";

/**
 * The scan pipeline end to end, without touching the filesystem.
 *
 * The exit code is the contract CI branches on, so it is pinned in both
 * directions: a failing control must be non-zero, and nothing else may be.
 */
const TOOL = { name: "ccm-scanner", version: "0.0.0-test" } as const;
const AT = "2026-07-20T00:00:00.000Z";

function fixture(name: string): string {
  return readFileSync(new URL(`../../fixtures/${name}`, import.meta.url), "utf8");
}

function options(overrides: Partial<ScanOptions> = {}): ScanOptions {
  return {
    controls: { kind: "all" },
    format: "both",
    failOn: "fail",
    out: "./out",
    ...overrides,
  };
}

function scan(name: string, overrides: Partial<ScanOptions> = {}): ScanResult {
  return runScan({
    raw: fixture(name),
    source: `fixtures/${name}`,
    options: options(overrides),
    tool: TOOL,
    generatedAt: AT,
  });
}

describe("exit codes", () => {
  it("is 0 when no control fails", () => {
    const result = scan("compliant/terraform-plan.json");
    expect(result.report.headline).toBe("pass");
    expect(result.exitCode).toBe(0);
  });

  it("is 1 when a control fails", () => {
    const result = scan("non-compliant/terraform-plan.json");
    expect(result.report.headline).toBe("fail");
    expect(result.exitCode).toBe(1);
  });

  // --fail-on none still reports the failures; it only declines to signal them
  // through the exit status.
  it("is 0 for a failing scan under --fail-on none, without softening the report", () => {
    const result = scan("non-compliant/terraform-plan.json", { failOn: "none" });
    expect(result.exitCode).toBe(0);
    expect(result.report.headline).toBe("fail");
    expect(result.report.controls.fail).toBeGreaterThan(0);
  });
});

describe("artifacts", () => {
  it("writes both documents for --format both", () => {
    expect(scan("compliant/terraform-plan.json").artifacts.map((a) => a.name)).toEqual([
      "report.json",
      "summary.md",
    ]);
  });

  it("writes only what was asked for", () => {
    expect(
      scan("compliant/terraform-plan.json", { format: "json" }).artifacts.map((a) => a.name),
    ).toEqual(["report.json"]);
    expect(
      scan("compliant/terraform-plan.json", { format: "md", out: undefined }).artifacts.map(
        (a) => a.name,
      ),
    ).toEqual(["summary.md"]);
  });

  it("is byte-identical for a fixed input and timestamp", () => {
    const first = scan("non-compliant/terraform-plan.json");
    const second = scan("non-compliant/terraform-plan.json");
    expect(first.artifacts).toEqual(second.artifacts);
  });

  it("records the input digest, and changes it when the input changes", () => {
    const compliant = scan("compliant/terraform-plan.json").report.metadata.input.digest;
    const nonCompliant = scan("non-compliant/terraform-plan.json").report.metadata.input.digest;
    expect(compliant).toMatch(/^[0-9a-f]{64}$/);
    expect(compliant).not.toBe(nonCompliant);
  });
});

describe("control selection", () => {
  function controlsIn(result: ScanResult): string[] {
    return [...new Set(result.report.verdicts.map((verdict) => verdict.ccmId))].sort();
  }

  it("scans everything by default", () => {
    const all = controlsIn(scan("compliant/terraform-plan.json"));
    expect(all.length).toBeGreaterThan(15);
    expect(all.some((id) => id.startsWith("IVS-"))).toBe(true);
  });

  it("narrows to a domain", () => {
    const iam = controlsIn(
      scan("compliant/terraform-plan.json", {
        controls: { kind: "some", domains: ["IAM"], ccmIds: [] },
      }),
    );
    expect(iam.every((id) => id.startsWith("IAM-"))).toBe(true);
    expect(iam.length).toBeGreaterThan(1);
  });

  it("narrows to a single control", () => {
    expect(
      controlsIn(
        scan("compliant/terraform-plan.json", {
          controls: { kind: "some", domains: [], ccmIds: ["CEK-12"] },
        }),
      ),
    ).toEqual(["CEK-12"]);
  });

  // A comma means union. Selecting a domain and a control from a *different*
  // domain must yield both, not the empty intersection of the two.
  it("unions a domain with a control from another domain", () => {
    const selected = controlsIn(
      scan("compliant/terraform-plan.json", {
        controls: { kind: "some", domains: ["IAM"], ccmIds: ["CEK-12"] },
      }),
    );
    expect(selected).toContain("CEK-12");
    expect(selected.some((id) => id.startsWith("IAM-"))).toBe(true);
    expect(selected.some((id) => id.startsWith("LOG-"))).toBe(false);
  });

  it("refuses a selector that matches nothing rather than passing vacuously", () => {
    expect(() =>
      scan("compliant/terraform-plan.json", {
        controls: { kind: "some", domains: [], ccmIds: ["IAM-99"] },
      }),
    ).toThrow(/IAM-99/);
  });

  // Narrowing must narrow the *report*, not just the work: a scan of one
  // domain must not claim coverage of the others.
  it("rolls up only the domains it scanned", () => {
    const result = scan("non-compliant/terraform-plan.json", {
      controls: { kind: "some", domains: ["IVS"], ccmIds: [] },
    });
    expect(result.report.domains.map((rollup) => rollup.domain)).toEqual(["IVS"]);
  });
});

describe("input warnings", () => {
  // A scan that quietly dropped part of its input produces a clean-looking
  // report over something it never read.
  it("carries ingest warnings into the report", () => {
    const raw = JSON.stringify({
      format_version: "1.2",
      planned_values: { root_module: { resources: [], child_modules: "not-an-array" } },
    });
    const result = runScan({
      raw,
      source: "memory:warning",
      options: options({ format: "json" }),
      tool: TOOL,
      generatedAt: AT,
    });
    expect(result.report.warnings.length).toBeGreaterThan(0);
    expect(result.artifacts[0]?.contents).toContain('"warnings"');
  });

  it("does not turn a warning into a failure", () => {
    const raw = JSON.stringify({
      format_version: "1.2",
      planned_values: { root_module: { resources: [], child_modules: "not-an-array" } },
    });
    const result = runScan({
      raw,
      source: "memory:warning",
      options: options(),
      tool: TOOL,
      generatedAt: AT,
    });
    expect(result.exitCode).toBe(0);
  });
});

describe("pipeline wiring", () => {
  // Redaction is tested directly in test/report/redact.test.ts; this pins that
  // the pipeline actually calls it, which is the part that matters for a
  // control whose purpose is "no renderer can emit a sensitive value".
  it("redacts sensitive values before rendering", () => {
    const raw = JSON.stringify({
      format_version: "1.2",
      values: {
        root_module: {
          resources: [
            {
              address: "aws_db_instance.main",
              mode: "managed",
              type: "aws_db_instance",
              name: "main",
              provider_name: "registry.terraform.io/hashicorp/aws",
              values: { storage_encrypted: false, password: "hunter2-not-real" },
              sensitive_values: { storage_encrypted: true, password: true },
            },
          ],
        },
      },
    });
    const result = runScan({
      raw,
      source: "memory:sensitive",
      options: options({ format: "both" }),
      tool: TOOL,
      generatedAt: AT,
    });
    for (const artifact of result.artifacts) {
      expect(artifact.contents, artifact.name).not.toContain("hunter2-not-real");
    }
    expect(result.artifacts[0]?.contents).toContain("redacted");
  });

  it("digests the input bytes, not the source label", () => {
    const raw = fixture("compliant/terraform-plan.json");
    const asFoo = runScan({
      raw,
      source: "a.json",
      options: options(),
      tool: TOOL,
      generatedAt: AT,
    });
    const asBar = runScan({
      raw,
      source: "b.json",
      options: options(),
      tool: TOOL,
      generatedAt: AT,
    });
    expect(asFoo.report.metadata.input.digest).toBe(asBar.report.metadata.input.digest);
    expect(asFoo.report.metadata.input.digest).toBe(createHash("sha256").update(raw).digest("hex"));
  });

  // Latent rather than reachable through parseControls, but it bypasses the
  // guard registry.select() exists to provide: no verdicts, headline "pass",
  // exit 0 — a vacuous clean bill of health.
  it("refuses an empty selection rather than passing vacuously", () => {
    expect(() =>
      scan("compliant/terraform-plan.json", {
        controls: { kind: "some", domains: [], ccmIds: [] },
      }),
    ).toThrow(/matched no registered checks/);
  });
});
