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
  const raw = readFileSync(new URL("../package.json", import.meta.url), "utf8");
  const { name, version } = JSON.parse(raw) as Manifest;
  return { name, version };
}

/**
 * Renders the M0 banner. `--version` / `-v` prints only the version line;
 * otherwise a short scaffold notice. The real `scan` CLI arrives in M5.
 */
export function formatBanner(manifest: Manifest, argv: readonly string[]): string {
  const versionLine = `${manifest.name} ${manifest.version}\n`;
  if (argv.includes("--version") || argv.includes("-v")) {
    return versionLine;
  }
  return (
    versionLine +
    "Read-only CCM v4.0 compliance scanner (scaffold).\n" +
    "The scan command lands in M5 — see docs/milestone-plan.md.\n"
  );
}
