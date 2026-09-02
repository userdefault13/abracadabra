import { describe, it, expect } from "vitest";
import { mountedVolumes, resolveVolumePath, volumesRootLabel } from "./volumes.js";
import { threeWayMerge, type Resolutions } from "./sync.js";
import type { Vault, VarEntry } from "./vault.js";
import { fingerprintsMatch } from "./tls-ephemeral.js";
import { createEphemeralTls } from "./tls-ephemeral.js";

function entry(value: string, updatedAt: number): VarEntry {
  return { value, secret: true, updatedAt };
}

function vault(projects: Vault["projects"]): Vault {
  return { version: 1, projects };
}

describe("volumes", () => {
  it("lists darwin volumes under /Volumes when present", () => {
    const vols = mountedVolumes("darwin");
    expect(Array.isArray(vols)).toBe(true);
  });

  it("resolves relative volume names per platform", () => {
    expect(resolveVolumePath("STICK", "darwin")).toBe("/Volumes/STICK");
    expect(volumesRootLabel("darwin")).toBe("/Volumes");
    expect(volumesRootLabel("linux")).toMatch(/media/);
  });
});

describe("threeWayMerge", () => {
  it("merges non-conflicting edits", () => {
    const base = vault({
      a: { createdAt: 1, vars: { K: entry("base", 1) } },
    });
    const ours = vault({
      a: { createdAt: 1, vars: { K: entry("ours", 2) } },
    });
    const theirs = vault({
      a: { createdAt: 1, vars: { K: entry("base", 1), N: entry("new", 3) } },
    });
    const { merged, conflicts, report } = threeWayMerge(ours, theirs, base, new Map(), "USB");
    expect(conflicts).toHaveLength(0);
    expect(merged.projects.a.vars.K.value).toBe("ours");
    expect(merged.projects.a.vars.N.value).toBe("new");
    expect(report.some((r) => r.includes("USB") || r.includes("var"))).toBe(true);
  });

  it("respects manual resolutions", () => {
    const base = vault({ a: { createdAt: 1, vars: { K: entry("base", 1) } } });
    const ours = vault({ a: { createdAt: 1, vars: { K: entry("ours", 5) } } });
    const theirs = vault({ a: { createdAt: 1, vars: { K: entry("theirs", 5) } } });
    const resolutions: Resolutions = new Map([["a/K", entry("theirs", 5)]]);
    const { merged, conflicts } = threeWayMerge(ours, theirs, base, resolutions, "peer");
    expect(conflicts).toHaveLength(0);
    expect(merged.projects.a.vars.K.value).toBe("theirs");
  });
});

describe("tls-ephemeral", () => {
  it("creates a self-signed cert with fingerprint", () => {
    const tls = createEphemeralTls("test-abra");
    expect(tls.cert).toContain("BEGIN CERTIFICATE");
    expect(tls.key).toContain("BEGIN");
    expect(tls.fingerprint).toMatch(/^[0-9A-F:]+$/);
    expect(fingerprintsMatch(tls.fingerprint, tls.fingerprint)).toBe(true);
    expect(fingerprintsMatch(tls.fingerprint, "00:11:22:33")).toBe(false);
  });
});
