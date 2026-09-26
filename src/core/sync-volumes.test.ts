import { describe, it, expect } from "vitest";
import { mountedVolumes, resolveVolumePath, volumesRootLabel } from "./volumes.js";
import { threeWayMerge, type Resolutions } from "./sync.js";
import type { Vault, VarEntry } from "./vault.js";
import { fingerprintsMatch } from "./tls-ephemeral.js";
import { createEphemeralTls, sanitizeCommonName } from "./tls-ephemeral.js";

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
    // posix separators for linux targets regardless of host OS
    expect(resolveVolumePath("STICK", "linux")).toMatch(/^\/(run\/media|media|mnt)\/(.+\/)?STICK$/);
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

  it("both sides changed → conflict (no silent newer-wins)", () => {
    const base = vault({ a: { createdAt: 1, vars: { K: entry("base", 1) } } });
    const ours = vault({ a: { createdAt: 1, vars: { K: entry("ours", 10) } } });
    const theirs = vault({ a: { createdAt: 1, vars: { K: entry("theirs", 20) } } });
    const { conflicts, merged } = threeWayMerge(ours, theirs, base, new Map(), "peer");
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0].key).toBe("K");
    expect(merged.projects.a.vars.K).toBeUndefined();
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
  it("creates a self-signed cert with full fingerprint", () => {
    const tls = createEphemeralTls("test-abra");
    expect(tls.cert).toContain("BEGIN CERTIFICATE");
    expect(tls.key).toContain("BEGIN");
    expect(tls.fingerprint).toMatch(/^[0-9A-F:]+$/);
    expect(tls.fingerprint.replace(/[^0-9A-Fa-f]/g, "")).toHaveLength(64);
    expect(fingerprintsMatch(tls.fingerprint, tls.fingerprint)).toBe(true);
    expect(fingerprintsMatch(tls.fingerprint, "00:11:22:33")).toBe(false);
  });

  it("sanitizes long / odd hostnames for the cert CN (≤ 64 chars)", () => {
    const long = "iad20-fj918-d363a433-4ea7-4abb-b61b-19dfc107f694-FAF4CDEBA9F8.local";
    expect(sanitizeCommonName(long).length).toBeLessThanOrEqual(64);
    expect(sanitizeCommonName("a/b=c d")).toBe("a-b-c-d");
    expect(sanitizeCommonName("///")).toBe("abracadabra-lan");
    const tls = createEphemeralTls(long);
    expect(tls.cert).toContain("BEGIN CERTIFICATE");
  });
});
