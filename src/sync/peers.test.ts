import { describe, it, expect } from "vitest";
import type { Vault } from "../core/vault.js";
import { generateSyncIdentity, getOrCreateSyncIdentity, identityFingerprint } from "./identity.js";
import {
  defaultPeerName,
  findPeer,
  oppositeRole,
  parseRole,
  PeerConflictError,
  planPeerUpsert,
  removePeer,
  resolveRoles,
  validatePeerName,
  type PeerCandidate,
} from "./peers.js";

function myVault(): Vault {
  return getOrCreateSyncIdentity({ version: 1, projects: {}, connections: {} }).vault;
}

function candidate(overrides: Partial<PeerCandidate> = {}): PeerCandidate {
  const id = generateSyncIdentity();
  return {
    id: id.id,
    name: "mini",
    ed25519: id.ed25519.publicKey,
    x25519: id.x25519.publicKey,
    role: "receiver",
    address: "100.64.0.2",
    ...overrides,
  };
}

describe("peer names", () => {
  it("validates lowercase [a-z0-9._-] up to 64", () => {
    expect(validatePeerName("mac-mini.local")).toBe("mac-mini.local");
    expect(validatePeerName("a".repeat(64))).toHaveLength(64);
    for (const bad of ["", "Mini", "a".repeat(65), "-lead", "has space", "__abra_x", "ü"]) {
      expect(() => validatePeerName(bad)).toThrow(/invalid peer name/);
    }
  });

  it("defaultPeerName sanitizes hostnames", () => {
    expect(defaultPeerName("Julius's MacBook-Pro.local")).toBe("julius-s-macbook-pro.local");
    expect(defaultPeerName("__weird__")).toBe("weird");
    expect(defaultPeerName("")).toBe("peer");
    expect(defaultPeerName("x".repeat(100))).toHaveLength(64);
  });
});

describe("roles", () => {
  it("are complementary", () => {
    expect(oppositeRole("source")).toBe("receiver");
    expect(resolveRoles("source")).toEqual({ listener: "source", connector: "receiver" });
    expect(resolveRoles("receiver", "source")).toEqual({ listener: "receiver", connector: "source" });
    expect(() => resolveRoles("source", "source")).toThrow(/role mismatch/);
    expect(() => resolveRoles("receiver", "receiver")).toThrow(/role mismatch/);
    expect(() => parseRole("admin")).toThrow(/invalid role/);
  });
});

describe("peers table re-pair rules", () => {
  it("adds a new peer with its identity fingerprint", () => {
    const v = myVault();
    const c = candidate();
    const plan = planPeerUpsert(v, c, { now: 5 });
    expect(plan.action).toBe("add");
    expect(plan.vault.syncPeers?.[c.id]).toEqual({
      name: "mini",
      idFingerprint: identityFingerprint(c.ed25519, c.x25519),
      ed25519: c.ed25519,
      x25519: c.x25519,
      role: "receiver",
      pairedAt: 5,
      lastAddress: "100.64.0.2",
    });
    expect(v.syncPeers).toBeUndefined(); // pure
  });

  it("same id + same keys → updates lastAddress (and name only when explicit)", () => {
    const c = candidate();
    const v1 = planPeerUpsert(myVault(), c, { now: 5 }).vault;
    const again = planPeerUpsert(v1, { ...c, name: "other-default", address: "100.64.0.9" }, { now: 99 });
    expect(again.action).toBe("update");
    expect(again.peer).toMatchObject({ name: "mini", lastAddress: "100.64.0.9", pairedAt: 5 });

    const renamed = planPeerUpsert(v1, { ...c, name: "studio" }, { explicitName: true });
    expect(renamed.peer.name).toBe("studio");
    expect(Object.keys(renamed.vault.syncPeers!)).toEqual([c.id]);
  });

  it("same id + different keys → always refused (even with --replace)", () => {
    const c = candidate();
    const v1 = planPeerUpsert(myVault(), c).vault;
    const other = generateSyncIdentity();
    for (const replace of [false, true]) {
      expect(() =>
        planPeerUpsert(v1, { ...c, ed25519: other.ed25519.publicKey, x25519: other.x25519.publicKey }, { replace }),
      ).toThrow(/different keys.*impersonation/);
      expect(() => planPeerUpsert(v1, { ...c, x25519: other.x25519.publicKey }, { replace })).toThrow(PeerConflictError);
    }
  });

  it("same name, different identity → refused unless --replace (shows old vs new fingerprint)", () => {
    const first = candidate();
    const v1 = planPeerUpsert(myVault(), first).vault;
    const second = candidate();
    const oldFp = identityFingerprint(first.ed25519, first.x25519);
    const newFp = identityFingerprint(second.ed25519, second.x25519);
    let msg = "";
    try {
      planPeerUpsert(v1, second);
    } catch (err) {
      msg = (err as Error).message;
    }
    expect(msg).toContain("--replace");
    expect(msg).toContain(oldFp);
    expect(msg).toContain(newFp);

    const replaced = planPeerUpsert(v1, second, { replace: true });
    expect(replaced.action).toBe("replace");
    expect(replaced.replaced).toEqual({ id: first.id, name: "mini", idFingerprint: oldFp });
    expect(Object.keys(replaced.vault.syncPeers!)).toEqual([second.id]);
  });

  it("refuses role changes and the vault's own identity", () => {
    const c = candidate();
    const v1 = planPeerUpsert(myVault(), c).vault;
    expect(() => planPeerUpsert(v1, { ...c, role: "source" })).toThrow(/already paired as receiver/);

    const own = v1.syncIdentity!;
    expect(() =>
      planPeerUpsert(v1, candidate({ id: own.id, name: "self" })),
    ).toThrow(/own sync identity/);
    expect(() =>
      planPeerUpsert(v1, candidate({ ed25519: own.ed25519.publicKey, name: "self" })),
    ).toThrow(/own sync identity/);
  });

  it("refuses the same keys under a different id", () => {
    const c = candidate();
    const v1 = planPeerUpsert(myVault(), c).vault;
    expect(() => planPeerUpsert(v1, { ...c, id: generateSyncIdentity().id, name: "dup" })).toThrow(
      /already paired as "mini"/,
    );
  });

  it("find / remove by name or id", () => {
    const c = candidate();
    const v1 = planPeerUpsert(myVault(), c).vault;
    expect(findPeer(v1, "mini")?.id).toBe(c.id);
    expect(findPeer(v1, c.id)?.peer.name).toBe("mini");
    expect(findPeer(v1, "nope")).toBeNull();
    const { vault, removed } = removePeer(v1, "mini");
    expect(removed.id).toBe(c.id);
    expect(vault.syncPeers).toEqual({});
    expect(() => removePeer(vault, "mini")).toThrow(/no paired peer/);
  });
});
