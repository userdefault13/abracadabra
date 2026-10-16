import type { SyncPeer, UnlockWrap, Vault } from "../core/vault.js";
import { findPeer } from "../sync/peers.js";
import { REMOTE_UNLOCK_PORT } from "./wire.js";

/**
 * Hub-side peer selection for `abra remote unlock|lock --all|--peers`.
 */

export class RemotePeerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RemotePeerError";
  }
}

export interface EnrolledPeer {
  id: string;
  name: string;
  peer: SyncPeer;
  unlockWrap: UnlockWrap;
  host: string;
  port: number;
}

/** Parse `--peers a,b` (comma-separated names or ids). */
export function parsePeersList(raw: string): string[] {
  const parts = String(raw)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.length === 0) {
    throw new RemotePeerError("empty --peers list — pass names like: --peers mini,omarchy");
  }
  return parts;
}

/**
 * Resolve enrolled receiver peers for a batch unlock/lock.
 * Requires either `all` or a non-empty `peers` list (not both empty).
 */
export function selectEnrolledPeers(
  vault: Vault,
  opts: { all?: boolean; peers?: string },
): EnrolledPeer[] {
  if (opts.all && opts.peers) {
    throw new RemotePeerError("pass either --all or --peers, not both");
  }
  if (!opts.all && !opts.peers) {
    throw new RemotePeerError("pass --all or --peers <a,b>");
  }

  const peers = vault.syncPeers ?? {};
  let selected: { id: string; peer: SyncPeer }[];

  if (opts.all) {
    selected = Object.entries(peers)
      .filter(([, p]) => p.role === "receiver" && p.unlockWrap)
      .map(([id, peer]) => ({ id, peer }));
    if (selected.length === 0) {
      throw new RemotePeerError("no enrolled receiver peers — run: abra remote enroll <peer>");
    }
  } else {
    const names = parsePeersList(opts.peers!);
    selected = names.map((name) => {
      const found = findPeer(vault, name);
      if (!found) throw new RemotePeerError(`no paired peer named "${name}" — see: abra sync peers`);
      if (found.peer.role !== "receiver") {
        throw new RemotePeerError(
          `peer "${found.peer.name}" is paired as ${found.peer.role} — only receivers can be unlocked remotely`,
        );
      }
      if (!found.peer.unlockWrap) {
        throw new RemotePeerError(
          `peer "${found.peer.name}" is not enrolled for remote unlock — run: abra remote enroll ${found.peer.name}`,
        );
      }
      return found;
    });
  }

  return selected.map(({ id, peer }) => {
    const host = peer.lastAddress;
    if (!host) {
      throw new RemotePeerError(
        `peer "${peer.name}" has no lastAddress — re-pair or set an address before remote unlock`,
      );
    }
    return {
      id,
      name: peer.name,
      peer,
      unlockWrap: peer.unlockWrap!,
      host,
      port: REMOTE_UNLOCK_PORT,
    };
  });
}

/** List enrolled receivers (for status); skips peers without unlockWrap. */
export function listEnrolledPeers(vault: Vault): EnrolledPeer[] {
  const peers = vault.syncPeers ?? {};
  const out: EnrolledPeer[] = [];
  for (const [id, peer] of Object.entries(peers)) {
    if (peer.role !== "receiver" || !peer.unlockWrap) continue;
    const host = peer.lastAddress ?? "";
    out.push({
      id,
      name: peer.name,
      peer,
      unlockWrap: peer.unlockWrap,
      host,
      port: REMOTE_UNLOCK_PORT,
    });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}
