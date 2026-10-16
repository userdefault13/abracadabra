import type { SyncPeer, SyncPeerRole, Vault } from "../core/vault.js";
import { identityFingerprint } from "./identity.js";

export const PEER_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export const SYNC_ROLES: readonly SyncPeerRole[] = ["source", "receiver"];

export function validatePeerName(name: string): string {
  if (typeof name !== "string" || !PEER_NAME_RE.test(name)) {
    throw new Error(
      `invalid peer name "${String(name)}" — use 1-64 chars of lowercase a-z, 0-9, ".", "_", "-" (starting with a letter or digit)`,
    );
  }
  return name;
}

/** Hostname → valid peer name ("Julius's MacBook.local" → "julius-s-macbook.local"). */
export function defaultPeerName(hostname: string): string {
  const cleaned = String(hostname ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[^a-z0-9]+/, "")
    .slice(0, 64)
    .replace(/[._-]+$/, "");
  return PEER_NAME_RE.test(cleaned) ? cleaned : "peer";
}

export function parseRole(value: string): SyncPeerRole {
  if (value === "source" || value === "receiver") return value;
  throw new Error(`invalid role "${value}" — expected "source" or "receiver"`);
}

export function oppositeRole(role: SyncPeerRole): SyncPeerRole {
  return role === "source" ? "receiver" : "source";
}

/**
 * Roles are complementary: the connector always gets the opposite of the
 * listener. An explicit connector role that would collide aborts pairing.
 */
export function resolveRoles(
  listenerRole: SyncPeerRole,
  connectorRequested?: SyncPeerRole | null,
): { listener: SyncPeerRole; connector: SyncPeerRole } {
  const connector = oppositeRole(listenerRole);
  if (connectorRequested && connectorRequested !== connector) {
    throw new Error(
      `role mismatch: the listening machine is the ${listenerRole}, so this side must be the ${connector} (got --role ${connectorRequested})`,
    );
  }
  return { listener: listenerRole, connector };
}

/** Human description of what pairing means for this machine. */
export function describeRoles(myRole: SyncPeerRole): string {
  return myRole === "source"
    ? "this machine = SOURCE (it will push projects to the peer) · peer = RECEIVER"
    : "this machine = RECEIVER (the peer will push projects here) · peer = SOURCE";
}

export interface PeerCandidate {
  id: string;
  name: string;
  ed25519: string;
  x25519: string;
  /** What the peer is relative to this vault. */
  role: SyncPeerRole;
  address?: string;
}

export interface PeerPlan {
  action: "add" | "update" | "replace";
  vault: Vault;
  peer: SyncPeer;
  replaced?: { id: string; name: string; idFingerprint: string };
}

export class PeerConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PeerConflictError";
  }
}

/**
 * Apply the re-pair rules (pure):
 * - same id + same keys → update name (only if explicitly given) and lastAddress
 * - same id + different keys → always refused (possible impersonation; unpair first)
 * - same name, different id/keys → refused unless `replace`
 * - the peer presenting this vault's own identity (cloned vault) → refused
 */
export function planPeerUpsert(
  vault: Vault,
  cand: PeerCandidate,
  opts: { replace?: boolean; explicitName?: boolean; now?: number } = {},
): PeerPlan {
  const own = vault.syncIdentity;
  if (
    own &&
    (cand.id === own.id ||
      cand.ed25519 === own.ed25519.publicKey ||
      cand.x25519 === own.x25519.publicKey)
  ) {
    throw new PeerConflictError(
      "the peer presents this vault's own sync identity (cloned vault?) — refusing; re-create the identity on one machine after restore",
    );
  }

  const candFp = identityFingerprint(cand.ed25519, cand.x25519);
  const peers: Record<string, SyncPeer> = { ...(vault.syncPeers ?? {}) };
  const existing = peers[cand.id];

  if (existing) {
    if (existing.ed25519 !== cand.ed25519 || existing.x25519 !== cand.x25519) {
      throw new PeerConflictError(
        `peer id ${cand.id} ("${existing.name}") is already paired with different keys ` +
          `(stored ${existing.idFingerprint}, presented ${candFp}) — possible impersonation. ` +
          `If that machine was really reset, run: abra sync unpair ${existing.name}`,
      );
    }
    if (existing.role !== cand.role) {
      throw new PeerConflictError(
        `peer "${existing.name}" is already paired as ${existing.role} — run abra sync unpair ${existing.name} first to change roles`,
      );
    }
  }

  for (const [otherId, other] of Object.entries(peers)) {
    if (otherId !== cand.id && other.ed25519 === cand.ed25519) {
      throw new PeerConflictError(
        `these keys are already paired as "${other.name}" under another id — run abra sync unpair ${other.name} first`,
      );
    }
  }

  const name = validatePeerName(existing && !opts.explicitName ? existing.name : cand.name);

  let replaced: PeerPlan["replaced"];
  const clash = Object.entries(peers).find(([otherId, p]) => otherId !== cand.id && p.name === name);
  if (clash) {
    const [clashId, clashPeer] = clash;
    if (!opts.replace) {
      throw new PeerConflictError(
        `peer name "${name}" is already used by a different identity ` +
          `(old ${clashPeer.idFingerprint}, new ${candFp}) — pass --replace to overwrite it, or --name <other>`,
      );
    }
    replaced = { id: clashId, name: clashPeer.name, idFingerprint: clashPeer.idFingerprint };
    delete peers[clashId];
  }

  const peer: SyncPeer = existing
    ? { ...existing, name, lastAddress: cand.address ?? existing.lastAddress }
    : {
        name,
        idFingerprint: candFp,
        ed25519: cand.ed25519,
        x25519: cand.x25519,
        role: cand.role,
        pairedAt: opts.now ?? Date.now(),
        ...(cand.address ? { lastAddress: cand.address } : {}),
      };
  peers[cand.id] = peer;

  return {
    action: replaced ? "replace" : existing ? "update" : "add",
    vault: { ...vault, syncPeers: peers },
    peer,
    replaced,
  };
}

/** Find by exact name or identity id. */
export function findPeer(vault: Vault, nameOrId: string): { id: string; peer: SyncPeer } | null {
  const peers = vault.syncPeers ?? {};
  if (peers[nameOrId]) return { id: nameOrId, peer: peers[nameOrId] };
  const hit = Object.entries(peers).find(([, p]) => p.name === nameOrId);
  return hit ? { id: hit[0], peer: hit[1] } : null;
}

/**
 * Remove a paired peer (and its unlockWrap, if any — remote unlock is revoked
 * by deleting the hub-held wrap key with the peer record).
 */
export function removePeer(vault: Vault, nameOrId: string): { vault: Vault; removed: { id: string; peer: SyncPeer } } {
  const found = findPeer(vault, nameOrId);
  if (!found) throw new Error(`no paired peer named "${nameOrId}" — see: abra sync peers`);
  const peers = { ...(vault.syncPeers ?? {}) };
  delete peers[found.id];
  const out: Vault = { ...vault, syncPeers: peers };
  if (vault.syncAccept) out.syncAccept = vault.syncAccept.filter((r) => r.from !== found.id);
  return { vault: out, removed: found };
}
