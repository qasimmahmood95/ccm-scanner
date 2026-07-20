import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main, runCli } from "../../src/cli/main.js";

/**
 * `main` driven in-process.
 *
 * `verify-fixtures.ts` covers the same ground through the built binary, which
 * is the thing users run; this covers it fast enough to run on every save, and
 * exists at all because `main.ts` has no side effects on import. The executable
 * shim is deliberately unconditional: deciding "am I the entry point?" from
 * `process.argv[1]` breaks an npm-installed binary, whose bin is a symlink.
 */
const COMPLIANT = "fixtures/compliant/terraform-plan.json";
const NON_COMPLIANT = "fixtures/non-compliant/terraform-plan.json";

let out = "";
let stdout: string[] = [];
let stderr: string[] = [];

beforeEach(() => {
  out = mkdtempSync(join(tmpdir(), "ccm-scanner-main-"));
  stdout = [];
  stderr = [];
  vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
    stdout.push(String(chunk));
    return true;
  });
  vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
    stderr.push(String(chunk));
    return true;
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  rmSync(out, { recursive: true, force: true });
});

describe("exit codes", () => {
  it("is 0 for a clean scan", () => {
    expect(main(["scan", "-i", COMPLIANT, "-o", out])).toBe(0);
  });

  it("is 1 when a control fails", () => {
    expect(main(["scan", "-i", NON_COMPLIANT, "-o", out])).toBe(1);
  });

  it("is 1 on the stdout path too, and writes the document", () => {
    expect(main(["scan", "-i", NON_COMPLIANT, "--format", "json"])).toBe(1);
    expect(stdout.join("")).toContain('"headline": "fail"');
  });

  it("is 0 under --fail-on none", () => {
    expect(main(["scan", "-i", NON_COMPLIANT, "--fail-on", "none", "-o", out])).toBe(0);
  });

  // Every misuse exits 2 through one path, and says something.
  const usage: readonly (readonly string[])[] = [
    ["scan"],
    ["scan", "-i", "nope.json"],
    ["scan", "-i", "fixtures"],
    ["scan", "-i", COMPLIANT, "--controls", "iam,nope"],
    ["scan", "-i", COMPLIANT, "--controls", "CEK-99"],
    ["scan", "-i", COMPLIANT, "--format", "xml"],
    ["scan", "-i", COMPLIANT, "--format", "both"],
    ["scan", "-i", COMPLIANT, "--out", ""],
    ["scan", "-i", COMPLIANT, "--out", "   "],
    ["scan", "-i", "package.json"],
    ["bogus"],
    ["help", "bogus"],
    ["scan", "-i", COMPLIANT, "--nope"],
  ];
  for (const argv of usage) {
    it(`exits 2 for \`${argv.join(" ")}\``, () => {
      expect(main(argv)).toBe(2);
      expect(stderr.join("").trim(), "an error must not be silent").not.toBe("");
    });
  }
});

describe("help and version", () => {
  // commander writes these itself; printing them again duplicated the output.
  for (const argv of [["--version"], ["-v"]]) {
    it(`\`${argv.join(" ")}\` prints one version line`, () => {
      expect(main(argv)).toBe(0);
      expect(stdout.join("").trim().split("\n")).toHaveLength(1);
    });
  }

  // commander writes the real reason to stderr and throws an error carrying
  // only the placeholder "(outputHelp)", so reporting the error's message left
  // the user with a meaningless string.
  it("help <unknown> reports usage rather than commander's placeholder", () => {
    expect(main(["help", "bogus"])).toBe(2);
    const reported = stderr.join("");
    expect(reported).toContain("Usage:");
    expect(reported).not.toContain("(outputHelp)");
  });

  // commander derives its exit code from the ambient process.exitCode.
  it("is unaffected by an exit code the caller already set", () => {
    const before = process.exitCode;
    process.exitCode = 1;
    try {
      expect(main(["help"])).toBe(0);
      expect(stderr.join("")).toBe("");
    } finally {
      process.exitCode = before;
    }
  });

  it("scan --help prints the scan help, not the root help", () => {
    expect(main(["scan", "--help"])).toBe(0);
    const printed = stdout.join("");
    expect(printed.split("Usage:")).toHaveLength(2);
    expect(printed).toContain("--fail-on");
  });
});

describe("runCli", () => {
  it("explains the tool when given no arguments", () => {
    expect(runCli([])).toBe(0);
    expect(stdout.join("")).toContain("scan --help");
  });
});

describe("the evidence pack", () => {
  it("writes both documents, and reports the outcome on stderr", () => {
    expect(main(["scan", "-i", NON_COMPLIANT, "--format", "both", "-o", out])).toBe(1);
    expect(readFileSync(join(out, "report.json"), "utf8")).toContain('"schemaVersion"');
    expect(readFileSync(join(out, "summary.md"), "utf8")).toContain("# ccm-scanner report");
    // stdout stays clean so `--format json --out dir` can be piped.
    expect(stdout.join("")).toBe("");
    expect(stderr.join("")).toContain("FAIL:");
  });

  it("mentions input warnings on stderr when there are any", () => {
    const warning = join(out, "warning.json");
    writeFileSync(
      warning,
      JSON.stringify({
        format_version: "1.2",
        planned_values: { root_module: { resources: [], child_modules: "not-an-array" } },
      }),
      "utf8",
    );
    expect(main(["scan", "-i", warning, "-o", out])).toBe(0);
    expect(stderr.join("")).toContain("input warning(s)");
  });
});
