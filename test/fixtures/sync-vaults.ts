import type { SyncIdentity, SyncPeer, SyncPeerRole, Vault, VarEntry } from "../../src/core/vault.js";
import { generateSyncIdentity, identityFingerprint } from "../../src/sync/identity.js";

export function entry(value: string, updatedAt = 1): VarEntry {
  return { value, secret: true, updatedAt };
}

export function peerRecord(id: SyncIdentity, name: string, role: SyncPeerRole): SyncPeer {
  return {
    name,
    idFingerprint: identityFingerprint(id.ed25519.publicKey, id.x25519.publicKey),
    ed25519: id.ed25519.publicKey,
    x25519: id.x25519.publicKey,
    role,
    pairedAt: 1,
  };
}

/**
 * A source vault ("mbp") paired with a receiver vault ("mini").
 * Source has app{A,B} + other{X}; receiver has app{B (different), LOCAL}.
 */
export function makePair() {
  const sourceId = generateSyncIdentity();
  const receiverId = generateSyncIdentity();
  const source: Vault = {
    version: 1,
    projects: {
      app: { createdAt: 1, vars: { A: entry("a-from-source"), B: entry("b-from-source") } },
      other: { createdAt: 1, vars: { X: entry("x-from-source") } },
    },
    connections: {},
    syncIdentity: sourceId,
    syncPeers: { [receiverId.id]: peerRecord(receiverId, "mini", "receiver") },
  };
  const receiver: Vault = {
    version: 1,
    projects: {
      app: { createdAt: 2, vars: { B: entry("b-local"), LOCAL: entry("only-here") } },
    },
    connections: {},
    syncIdentity: receiverId,
    syncPeers: { [sourceId.id]: peerRecord(sourceId, "mbp", "source") },
  };
  return { source, receiver, sourceId, receiverId };
}
