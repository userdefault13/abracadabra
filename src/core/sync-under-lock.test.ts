import { describe, it, expect } from "vitest";
import type { Vault, VarEntry } from "./vault.js";
import { remergeUnderLock, threeWayMerge, VaultChangedDuringSyncError } from "./sync.js";
import { LanPushRefusedError, planLanPush } from "../usb/lan-host.js";

function e(value: string, updatedAt = 1): VarEntry {
  return { value, secret: true, updatedAt };
}

function vault(projects: Record<string, Record<string, VarEntry>>): Vault {
  return {
    version: 1,
    connections: {},
    projects: Object.fromEntries(Object.entries(projects).map(([n, vars]) => [n, { createdAt: 1, vars }])),
  };
}

describe("remergeUnderLock", () => {
  const base = vault({ app: { A: e("a0"), B: e("b0") } });
  const theirs = vault({ app: { A: e("a-peer", 5), B: e("b0"), C: e("c-peer", 5) } });

  it("applies the previewed resolutions and keeps changes made here meanwhile", () => {
    const ours = vault({ app: { A: e("a-here", 4), B: e("b0") } });
    const preview = threeWayMerge(ours, theirs, base, new Map());
    expect(preview.conflicts.map((c) => c.key)).toEqual(["A"]);
    const resolutions = new Map([["app/A", e("a-peer", 5)]]);

    // While the user answered, another process added a project and changed B here.
    const fresh = vault({ app: { A: e("a-here", 4), B: e("b-new", 6) }, extra: { X: e("x") } });
    const r = remergeUnderLock(fresh, theirs, base, preview, resolutions);
    expect(r.merged.projects.app.vars.A.value).toBe("a-peer");
    expect(r.merged.projects.app.vars.B.value).toBe("b-new");
    expect(r.merged.projects.app.vars.C.value).toBe("c-peer");
    expect(r.merged.projects.extra.vars.X.value).toBe("x");
  });

  it("refuses when the conflict set changed since the preview", () => {
    const ours = vault({ app: { A: e("a-here", 4), B: e("b0") } });
    const preview = threeWayMerge(ours, theirs, base, new Map());
    const resolutions = new Map([["app/A", e("a-here", 4)]]);
    const fresh = vault({ app: { A: e("a-edited-again", 7), B: e("b0") } });
    expect(() => remergeUnderLock(fresh, theirs, base, preview, resolutions)).toThrow(VaultChangedDuringSyncError);
  });

  it("refuses when project deletions changed since the preview", () => {
    const ours = vault({ app: { A: e("a0"), B: e("b0") } });
    const preview = threeWayMerge(ours, theirs, base, new Map());
    expect(preview.projectDeletions).toEqual([]);
    const fresh = vault({}); // app deleted here meanwhile
    expect(() => remergeUnderLock(fresh, theirs, base, preview, new Map())).toThrow(VaultChangedDuringSyncError);
  });
});

describe("planLanPush (LAN host, under the vault lock)", () => {
  const served = vault({ app: { A: e("a0") } });

  it("replaces the vault when it is unchanged since the peer pulled it", () => {
    const pushed = vault({ app: { A: e("a-peer", 5) } });
    expect(planLanPush(served, pushed, served, false).projects.app.vars.A.value).toBe("a-peer");
  });

  it("merges host edits made after the pull instead of overwriting them", () => {
    const fresh = vault({ app: { A: e("a0") }, hostNew: { H: e("h", 6) } });
    const pushed = vault({ app: { A: e("a-peer", 5) } });
    const next = planLanPush(fresh, pushed, served, false);
    expect(next.projects.app.vars.A.value).toBe("a-peer");
    expect(next.projects.hostNew.vars.H.value).toBe("h");
  });

  it("refuses a push that conflicts with a host edit made after the pull", () => {
    const fresh = vault({ app: { A: e("a-host", 6) } });
    const pushed = vault({ app: { A: e("a-peer", 5) } });
    expect(() => planLanPush(fresh, pushed, served, false)).toThrow(LanPushRefusedError);
  });

  it("still gates whole-project deletions on --allow-deletes", () => {
    const fresh = vault({ app: { A: e("a0") }, gone: { G: e("g") } });
    const pushed = vault({ app: { A: e("a0") } });
    expect(() => planLanPush(fresh, pushed, undefined, false)).toThrow(/would delete project/);
    expect(Object.keys(planLanPush(fresh, pushed, undefined, true).projects)).toEqual(["app"]);
  });
});
