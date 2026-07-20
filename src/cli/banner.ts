import { readFileSync } from "node:fs";

export interface Manifest {
  readonly name: string;
  readonly version: string;
}

/**
 * Reads the tool's name and version from the bundled package.json.
 *
 * Resolves relative to this module, so it works both from `dist/` (published)
 * and from `src/` (via tsx / vitest).
 */
export function readManifest(): Manifest {
  const raw = readFileSync(new URL("../../package.json", import.meta.url), "utf8");
  const { name, version } = JSON.parse(raw) as Manifest;
  return { name, version };
}

/**
 * What the tool prints when run with no arguments.
 *
 * Flag handling belongs to commander, which owns `--help` and `--version`;
 * this is only the "you ran it bare, here is what it is" case.
 */
export function formatBanner(manifest: Manifest): string {
  return (
    `${manifest.name} ${manifest.version}\n` +
    "Read-only CCM v4.0 compliance scanner for Terraform.\n" +
    `Run \`${manifest.name} scan --help\` to get started.\n`
  );
}
