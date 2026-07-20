/**
 * Regenerates the committed sample reports in `docs/samples/`.
 *
 * They exist so the shape of an evidence pack can be read without running
 * anything, and so a diff shows a real change in what the scanner concluded.
 * The timestamp is fixed for that reason: a regenerated sample that differs
 * only by `generatedAt` is noise that trains people to skim the diff.
 *
 * Like `verify-fixtures.ts`, this drives the built binary and lives outside
 * `src/`, which `package.json#files` excludes from the published tarball.
 */
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const CLI = "dist/cli/index.js";
const AT = "2026-07-21T00:00:00.000Z";

const samples: readonly { readonly input: string; readonly name: string }[] = [
  { input: "fixtures/compliant/terraform-plan.json", name: "terraform-compliant" },
  { input: "fixtures/non-compliant/terraform-plan.json", name: "terraform-non-compliant" },
  { input: "fixtures/snapshot/non-compliant.json", name: "snapshot-non-compliant" },
];

let failed = 0;
for (const sample of samples) {
  const out = join("docs", "samples", sample.name);
  const result = spawnSync(
    process.execPath,
    [
      CLI,
      "scan",
      "-i",
      sample.input,
      "--format",
      "both",
      "--out",
      out,
      "--generated-at",
      AT,
      // A failing sample is the point of two of these, so a non-zero exit here
      // would be reporting success as an error.
      "--fail-on",
      "none",
    ],
    { encoding: "utf8" },
  );
  if (result.status !== 0) {
    failed += 1;
    process.stdout.write(`FAIL ${sample.name}: exit ${String(result.status)}\n${result.stderr}`);
    continue;
  }
  process.stdout.write(`ok   ${sample.name}\n`);
}

if (failed > 0) {
  process.exitCode = 1;
} else {
  process.stdout.write("samples updated\n");
}
