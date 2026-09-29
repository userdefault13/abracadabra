import { describe, it, expect } from "vitest";
import { pickLatestRelease } from "./update.js";

const pkg = (version: string) => ({
  version,
  url: `https://cdn.aarcadeghst.com/releases/abracadabra/${version}/abracadabra-${version}-macos.pkg`,
});

describe("pickLatestRelease", () => {
  it("a stale CDN manifest never hides a newer npm release", () => {
    expect(pickLatestRelease(pkg("1.0.2"), { version: "1.0.6" }, "darwin")).toEqual({
      manifest: { version: "1.0.6" },
      source: "npm",
    });
  });

  it("macOS keeps the CDN .pkg when it is at least as new", () => {
    expect(pickLatestRelease(pkg("1.0.6"), { version: "1.0.6" }, "darwin")?.source).toBe("cdn");
    expect(pickLatestRelease(pkg("1.0.7"), { version: "1.0.6" }, "darwin")?.source).toBe("cdn");
  });

  it("Linux/Windows ignore the macOS .pkg", () => {
    expect(pickLatestRelease(pkg("1.0.9"), { version: "1.0.6" }, "linux")).toEqual({
      manifest: { version: "1.0.6" },
      source: "npm",
    });
    expect(pickLatestRelease(pkg("1.0.9"), null, "win32")).toBeNull();
  });

  it("falls back to whichever source answered", () => {
    expect(pickLatestRelease(null, { version: "1.0.6" }, "linux")?.source).toBe("npm");
    expect(pickLatestRelease(pkg("1.0.2"), null, "darwin")?.source).toBe("cdn");
    expect(pickLatestRelease(null, null, "darwin")).toBeNull();
  });
});
