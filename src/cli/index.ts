#!/usr/bin/env node
/**
 * The executable entry point: the only place that reads the scanned input or
 * writes the evidence pack.
 *
 * (`banner.ts` also reads the bundled package.json, for the tool's own version.
 * Read-only, and not the scanned input.)
 *
 * Nothing here writes to the input, executes Terraform, or issues a network
 * call — and nothing else under `src/` can, which makes the read-only posture a
 * property of the code rather than a promise in the README (hard constraints 1
 * and 2).
 */
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Command } from "commander";
import { formatBanner, readManifest } from "./banner.js";
import {
  parseControls,
  parseFailOn,
  parseFormat,
  UsageError,
  validateDestination,
  type ScanOptions,
} from "./options.js";
import { runScan } from "./run.js";

/** Exit codes are part of the contract, so CI can branch on them. */
const EXIT_USAGE = 2;

interface RawScanFlags {
  readonly input: string;
  readonly controls: string;
  readonly format: string;
  readonly failOn: string;
  readonly out?: string;
  readonly generatedAt?: string;
}

/** Reads the input, refusing a directory with a message that says what to do. */
function readInput(path: string): string {
  let isDirectory: boolean;
  try {
    isDirectory = statSync(path).isDirectory();
  } catch {
    throw new UsageError(`--input "${path}" does not exist or cannot be read.`);
  }
  if (isDirectory) {
    throw new UsageError(
      `--input "${path}" is a directory. This version reads the JSON produced by ` +
        "`terraform show -json` (of a saved plan file or of state). Scanning an HCL " +
        "directory is not implemented — see docs/milestone-plan.md.",
    );
  }
  return readFileSync(path, "utf8");
}

function toOptions(flags: RawScanFlags): ScanOptions {
  const format = parseFormat(flags.format);
  validateDestination(format, flags.out);
  return {
    controls: parseControls(flags.controls),
    format,
    failOn: parseFailOn(flags.failOn),
    out: flags.out,
  };
}

function scan(flags: RawScanFlags): number {
  const options = toOptions(flags);
  const raw = readInput(flags.input);

  const result = runScan({
    raw,
    source: flags.input,
    options,
    tool: readManifest(),
    generatedAt: flags.generatedAt ?? new Date().toISOString(),
  });

  if (options.out === undefined) {
    // Exactly one artifact here — validateDestination rejects `both` without
    // --out — so stdout stays a single parseable document.
    for (const artifact of result.artifacts) {
      process.stdout.write(artifact.contents);
    }
    return result.exitCode;
  }

  const directory = resolve(options.out);
  mkdirSync(directory, { recursive: true });
  for (const artifact of result.artifacts) {
    writeFileSync(join(directory, artifact.name), artifact.contents, "utf8");
  }

  // The summary goes to stderr so `--format json --out dir` leaves stdout
  // clean for a pipeline.
  const { controls } = result.report;
  process.stderr.write(
    `${result.report.headline.toUpperCase()}: ${String(controls.fail)} failed, ` +
      `${String(controls.pass)} passed, ${String(controls.notApplicable)} not applicable ` +
      `across ${String(controls.total)} controls.\n` +
      `Evidence pack written to ${directory}\n`,
  );
  if (result.report.warnings.length > 0) {
    process.stderr.write(
      `${String(result.report.warnings.length)} input warning(s) recorded in the report; ` +
        "the scan did not fully read its input.\n",
    );
  }
  return result.exitCode;
}

export function main(argv: readonly string[]): number {
  const manifest = readManifest();
  const program = new Command()
    .name(manifest.name)
    .description("Read-only CCM v4.0 compliance scanner for Terraform")
    // `-v` as well as `-V`: it printed the version through M4, and a CLI that
    // stops answering a flag it used to answer is a regression whatever the
    // convention says.
    .version(manifest.version, "-v, --version")
    // Errors come back to us rather than calling process.exit, so every misuse
    // exits through one path with one shape.
    .exitOverride()
    .configureOutput({ writeErr: () => undefined });

  let code = 0;
  program
    .command("scan")
    .description("Scan a Terraform plan or state JSON document against the CCM subset")
    .requiredOption("-i, --input <path>", "`terraform show -json` output to scan")
    .option("-c, --controls <list>", "all | domains (iam,log,cek,ivs) | ids (IAM-05,CEK-12)", "all")
    .option("-f, --format <format>", "json | md | both", "md")
    .option("-o, --out <dir>", "write the evidence pack here instead of stdout")
    .option("--fail-on <mode>", "fail (non-zero exit on any failing control) | none", "fail")
    .option("--generated-at <iso>", "fix the report timestamp, for reproducible output")
    .action((flags: RawScanFlags) => {
      code = scan(flags);
    });

  try {
    program.parse([...argv], { from: "user" });
  } catch (error) {
    // commander throws for --help and --version too, and neither is a failure.
    // It has *already* written them to stdout by this point — only stderr is
    // suppressed above — so printing anything here duplicates the output, and
    // for `scan --help` appends the wrong (root) help document.
    const commanderCode = (error as { code?: string }).code;
    if (
      commanderCode === "commander.helpDisplayed" ||
      commanderCode === "commander.help" ||
      commanderCode === "commander.version"
    ) {
      return 0;
    }
    if (error instanceof UsageError) {
      process.stderr.write(`${error.message}\n`);
      return EXIT_USAGE;
    }
    process.stderr.write(
      `${error instanceof Error ? error.message : String(error)}\n` +
        `Run \`${manifest.name} scan --help\` for usage.\n`,
    );
    return EXIT_USAGE;
  }
  return code;
}

/** Entry: a bare invocation explains the tool; anything else is parsed. */
export function runCli(argv: readonly string[]): number {
  if (argv.length === 0) {
    // No arguments is not an error: say what this is and how to start.
    process.stdout.write(formatBanner(readManifest()));
    return 0;
  }
  return main(argv);
}

// Only when executed as a program. The tests import this module to drive
// `main` over the stdout path, and importing it must not print a banner or set
// an exit code.
const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  process.exitCode = runCli(process.argv.slice(2));
}
