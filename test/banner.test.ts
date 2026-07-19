import { describe, expect, it } from "vitest";
import { formatBanner, readManifest, type Manifest } from "../src/banner.js";

const manifest: Manifest = { name: "ccm-scanner", version: "9.9.9" };

describe("formatBanner", () => {
  it("prints only the version line for --version", () => {
    expect(formatBanner(manifest, ["--version"])).toBe("ccm-scanner 9.9.9\n");
  });

  it("prints only the version line for -v", () => {
    expect(formatBanner(manifest, ["-v"])).toBe("ccm-scanner 9.9.9\n");
  });

  it("prints the scaffold banner when no flags are given", () => {
    const out = formatBanner(manifest, []);
    expect(out).toContain("ccm-scanner 9.9.9");
    expect(out).toContain("scaffold");
  });
});

describe("readManifest", () => {
  it("reads this package's real name and semver version", () => {
    const m = readManifest();
    expect(m.name).toBe("ccm-scanner");
    expect(m.version).toMatch(/^\d+\.\d+\.\d+/);
  });
});
