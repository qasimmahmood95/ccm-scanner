import { describe, expect, it } from "vitest";
import { formatBanner, readManifest, type Manifest } from "../../src/cli/banner.js";

const manifest: Manifest = { name: "ccm-scanner", version: "9.9.9" };

describe("formatBanner", () => {
  it("names the tool and its version", () => {
    expect(formatBanner(manifest)).toContain("ccm-scanner 9.9.9");
  });

  // The bare-invocation text is the first thing a new user sees, and through
  // M4 it still said the scan command had not shipped yet.
  it("points at the scan command rather than describing a scaffold", () => {
    const out = formatBanner(manifest);
    expect(out).toContain("scan --help");
    expect(out).not.toContain("scaffold");
    expect(out).not.toContain("M5");
  });
});

describe("readManifest", () => {
  it("reads this package's real name and semver version", () => {
    const found = readManifest();
    expect(found.name).toBe("ccm-scanner");
    expect(found.version).toMatch(/^\d+\.\d+\.\d+/);
  });
});
