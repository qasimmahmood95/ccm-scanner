/**
 * Runs the built CLI over the committed fixtures and asserts its exit codes.
 *
 * This is the half of the fixtures-as-gate that M3 could not land: asserting an
 * exit code needs something with an exit code. The unit suite already checks
 * which controls fire; what this adds is that the *binary* a user runs signals
 * the same thing, which is what CI and a pre-merge hook actually branch on.
 *
 * `spawnSync` lives here, in a development script — never in `src/`, where the
 * read-only posture means the scanner cannot reach a process at all.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI = "dist/cli/index.js";

interface Case {
  readonly name: string;
  readonly args: readonly string[];
  readonly expected: number;
}

const out = mkdtempSync(join(tmpdir(), "ccm-scanner-verify-"));

const cases: readonly Case[] = [
  {
    name: "compliant fixture exits 0",
    args: ["scan", "-i", "fixtures/compliant/terraform-plan.json", "--format", "json", "-o", out],
    expected: 0,
  },
  {
    name: "non-compliant fixture exits 1",
    args: [
      "scan",
      "-i",
      "fixtures/non-compliant/terraform-plan.json",
      "--format",
      "json",
      "-o",
      out,
    ],
    expected: 1,
  },
  {
    name: "--fail-on none exits 0 even with failures",
    args: [
      "scan",
      "-i",
      "fixtures/non-compliant/terraform-plan.json",
      "--fail-on",
      "none",
      "--format",
      "json",
      "-o",
      out,
    ],
    expected: 0,
  },
  {
    name: "a mistyped selector is a usage error, not a silent pass",
    args: ["scan", "-i", "fixtures/compliant/terraform-plan.json", "--controls", "iam,nope"],
    expected: 2,
  },
  {
    name: "a missing input is a usage error",
    args: ["scan", "-i", "fixtures/does-not-exist.json"],
    expected: 2,
  },
];

let failures = 0;
for (const testCase of cases) {
  const result = spawnSync(process.execPath, [CLI, ...testCase.args], { encoding: "utf8" });
  const actual = result.status;
  const ok = actual === testCase.expected;
  if (!ok) {
    failures += 1;
  }
  process.stdout.write(
    `${ok ? "ok  " : "FAIL"} ${testCase.name} (expected ${String(testCase.expected)}, ` +
      `got ${String(actual)})\n`,
  );
  if (!ok && result.stderr !== "") {
    process.stdout.write(`     stderr: ${result.stderr.trim()}\n`);
  }
}

/**
 * The non-compliant report must name the controls the fixture is built to
 * violate. An exit code alone would pass if the scanner failed everything for
 * the wrong reason.
 */
const report = JSON.parse(readFileSync(join(out, "report.json"), "utf8")) as {
  verdicts: readonly { ccmId: string; status: string }[];
};
const failed = new Set(
  report.verdicts.filter((verdict) => verdict.status === "fail").map((verdict) => verdict.ccmId),
);
for (const expected of ["IAM-05", "IAM-16", "CEK-03", "CEK-12", "LOG-07", "IVS-03", "IVS-06"]) {
  const ok = failed.has(expected);
  if (!ok) {
    failures += 1;
  }
  process.stdout.write(`${ok ? "ok  " : "FAIL"} non-compliant fixture flags ${expected}\n`);
}

rmSync(out, { recursive: true, force: true });

if (failures > 0) {
  process.stdout.write(`\n${String(failures)} check(s) failed\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("\nall fixture checks passed\n");
}
