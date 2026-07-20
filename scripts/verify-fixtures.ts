/**
 * Runs the built CLI over the committed fixtures and asserts its behaviour.
 *
 * This is the half of the fixtures-as-gate that M3 could not land: asserting an
 * exit code needs something with an exit code. The unit suite already checks
 * which controls fire; what this adds is that the *binary* a user runs signals
 * the same thing, which is what CI and a pre-merge hook actually branch on.
 *
 * `spawnSync` lives here, in a development script that `package.json#files`
 * excludes from the published tarball — never in `src/`, where the read-only
 * posture means the scanner cannot reach a process at all.
 */
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const CLI = "dist/cli/index.js";
const COMPLIANT = "fixtures/compliant/terraform-plan.json";
const NON_COMPLIANT = "fixtures/non-compliant/terraform-plan.json";

const workspace = mkdtempSync(join(tmpdir(), "ccm-scanner-verify-"));
let failures = 0;

function run(args: readonly string[]): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
}

function check(name: string, ok: boolean, detail = ""): void {
  if (!ok) {
    failures += 1;
  }
  process.stdout.write(`${ok ? "ok  " : "FAIL"} ${name}${detail === "" ? "" : ` — ${detail}`}\n`);
}

function expectExit(name: string, args: readonly string[], expected: number): void {
  const result = run(args);
  check(
    name,
    result.status === expected,
    `expected ${String(expected)}, got ${String(result.status)}`,
  );
}

/** Each case writes to its own directory, so no assertion depends on case order. */
function outDir(name: string): string {
  return join(workspace, name);
}

// --- exit codes, writing an evidence pack -----------------------------------
expectExit("compliant fixture exits 0", ["scan", "-i", COMPLIANT, "-o", outDir("compliant")], 0);
expectExit(
  "non-compliant fixture exits 1",
  ["scan", "-i", NON_COMPLIANT, "--format", "both", "-o", outDir("non-compliant")],
  1,
);
expectExit(
  "--fail-on none exits 0 even with failures",
  ["scan", "-i", NON_COMPLIANT, "--fail-on", "none", "-o", outDir("fail-on-none")],
  0,
);

// --- exit codes on the default path, which writes to stdout ------------------
// The most likely real invocation, and the one a `-o`-only gate leaves ungated.
for (const format of ["md", "json"] as const) {
  const failing = run(["scan", "-i", NON_COMPLIANT, "--format", format]);
  check(
    `--format ${format} to stdout exits 1 for a failing scan`,
    failing.status === 1,
    `got ${String(failing.status)}`,
  );
  check(`--format ${format} to stdout emits a document`, failing.stdout.trim().length > 0);

  const passing = run(["scan", "-i", COMPLIANT, "--format", format]);
  check(
    `--format ${format} to stdout exits 0 for a clean scan`,
    passing.status === 0,
    `got ${String(passing.status)}`,
  );
}

const jsonOnStdout = run(["scan", "-i", COMPLIANT, "--format", "json"]);
try {
  JSON.parse(jsonOnStdout.stdout);
  check("--format json writes parseable JSON to stdout", true);
} catch {
  check("--format json writes parseable JSON to stdout", false, "stdout was not valid JSON");
}

// --- usage errors, which must never be a silent pass ------------------------
expectExit("a mistyped selector is a usage error", ["scan", "-i", COMPLIANT, "-c", "iam,nope"], 2);
expectExit("an unknown control id is a usage error", ["scan", "-i", COMPLIANT, "-c", "CEK-99"], 2);
expectExit("a missing input is a usage error", ["scan", "-i", "fixtures/does-not-exist.json"], 2);
expectExit("a directory input is a usage error", ["scan", "-i", "fixtures"], 2);
expectExit("an empty --out is a usage error", ["scan", "-i", COMPLIANT, "-o", ""], 2);
expectExit(
  "--format both without --out is a usage error",
  ["scan", "-i", COMPLIANT, "-f", "both"],
  2,
);
expectExit("a malformed document is a usage error", ["scan", "-i", "package.json"], 2);

// --- --help and --version print once, and only what was asked for -----------
const version = run(["--version"]);
check(
  "--version prints exactly one line",
  version.status === 0 && version.stdout.trim().split("\n").length === 1,
  JSON.stringify(version.stdout),
);
// `-v` was a merge blocker last round; nothing pinned it.
const shortVersion = run(["-v"]);
check(
  "-v prints the version",
  shortVersion.status === 0 && shortVersion.stdout.trim() === version.stdout.trim(),
  JSON.stringify(shortVersion.stdout),
);

// commander reports an unknown subcommand through the stderr we suppress, so
// this was silent and 0 until its exit code was honoured.
const unknownHelp = run(["help", "bogus"]);
check(
  "help <unknown> reports an error rather than exiting 0 in silence",
  unknownHelp.status === 2 && unknownHelp.stderr.trim().length > 0,
  `exit ${String(unknownHelp.status)}, stderr ${String(unknownHelp.stderr.length)}B`,
);
expectExit("an unknown command is a usage error", ["bogus"], 2);
expectExit("a whitespace --out is a usage error", ["scan", "-i", COMPLIANT, "-o", "   "], 2);

const scanHelp = run(["scan", "--help"]);
check(
  "scan --help prints the scan help once, without the root help",
  scanHelp.status === 0 &&
    scanHelp.stdout.split("Usage:").length === 2 &&
    scanHelp.stdout.includes("--fail-on"),
);

// --- the shim actually runs when imported as a program ----------------------
// MB-A: a guard on process.argv[1] made the npm-installed binary a silent
// no-op, because npm installs the bin as a symlink and Node realpaths
// import.meta.url but not argv[1]. Importing the shim from a *different* entry
// point reproduces that divergence without needing a symlink, so the blocker
// cannot come back green.
const imported = spawnSync(
  process.execPath,
  [
    "--input-type=module",
    "-e",
    `await import(${JSON.stringify(pathToFileURL(resolve(CLI)).href)})`,
  ],
  { encoding: "utf8" },
);
check(
  "the shim runs when its module URL differs from argv[1]",
  imported.stdout.includes("scan --help"),
  `stdout ${String(imported.stdout.length)}B`,
);

// --- the pack is byte-reproducible for a fixed input and timestamp ----------
const AT = "2026-01-01T00:00:00.000Z";
for (const run of ["repro-a", "repro-b"]) {
  expectExit(
    `reproducible run ${run} exits 1`,
    ["scan", "-i", NON_COMPLIANT, "--format", "both", "--generated-at", AT, "-o", outDir(run)],
    1,
  );
}
for (const artifact of ["report.json", "summary.md"]) {
  const a = readFileSync(join(outDir("repro-a"), artifact), "utf8");
  const b = readFileSync(join(outDir("repro-b"), artifact), "utf8");
  check(`${artifact} is byte-identical across runs with a fixed --generated-at`, a === b);
}
check(
  "--generated-at is the timestamp that lands in the report",
  readFileSync(join(outDir("repro-a"), "report.json"), "utf8").includes(`"generatedAt": "${AT}"`),
);

/**
 * The non-compliant report must name the controls the fixture is built to
 * violate. An exit code alone would pass if the scanner failed everything for
 * the wrong reason.
 */
const report = JSON.parse(readFileSync(join(outDir("non-compliant"), "report.json"), "utf8")) as {
  verdicts: readonly { ccmId: string; status: string }[];
};
const failed = new Set(
  report.verdicts.filter((verdict) => verdict.status === "fail").map((verdict) => verdict.ccmId),
);
for (const expected of [
  "IAM-05",
  "IAM-16",
  "CEK-03",
  "CEK-12",
  "LOG-07",
  "LOG-03",
  "IVS-03",
  "IVS-06",
]) {
  check(`non-compliant fixture flags ${expected}`, failed.has(expected));
}

// Nothing Terraform marked sensitive may reach either artifact.
for (const artifact of ["report.json", "summary.md"]) {
  const contents = readFileSync(join(outDir("non-compliant"), artifact), "utf8");
  check(
    `${artifact} contains no value marked sensitive in the fixture`,
    !contents.includes("example-not-a-real-password"),
  );
}

rmSync(workspace, { recursive: true, force: true });

if (failures > 0) {
  process.stdout.write(`\n${String(failures)} check(s) failed\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("\nall fixture checks passed\n");
}
