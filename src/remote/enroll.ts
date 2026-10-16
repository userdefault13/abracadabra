import type { SyncIdentity, UnlockWrap, Vault, VaultMutator } from "../core/vault.js";
import { findPeer } from "../sync/peers.js";
import { assertValidPublicKeys, isUuid } from "../sync/identity.js";
import type { DeviceKey } from "./device-key.js";
import { getOrCreateDeviceKey, publicDeviceKey } from "./device-key.js";
import { setHubPin, type HubPin } from "./hub-pin.js";
import {
  openWrapKeyFromOffer,
  parseEnrollOffer,
  sealWrapKeyForHub,
  type EnrollOffer,
} from "./enroll-seal.js";
import {
  createAndWriteUnlockBlob,
  encodeWrapKey,
  generateWrapKey,
  masterKeyFingerprint,
  type UnlockBlobFile,
} from "./unlock-blob.js";

/**
 * Remote unlock enroll (PR 2): receiver wraps its master key under W, seals W
 * to the hub, hub stores W in syncPeers[id].unlockWrap after Touch ID.
 *
 * Network transport is PR 3 — use {@link enrollLoopback} (or inject a transport)
 * until then. Never hold the vault lock across prompts / Touch ID / network.
 */

export type { EnrollOffer };

export class EnrollError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnrollError";
  }
}

export interface ReceiverEnrollInput {
  /** Unlocked receiver vault (must have sync identity + hub paired as source). */
  vault: Vault;
  masterKey: Buffer;
  /** abraDir for device-key / hub-pin / blob. */
  base: string;
  /** Hub peer name or id as known on this receiver (role must be source). */
  hubNameOrId: string;
  now?: number;
  /** Injected device key (tests); default: getOrCreateDeviceKey(base). */
  deviceKey?: DeviceKey;
}

export interface ReceiverEnrollResult {
  offer: EnrollOffer;
  blob: UnlockBlobFile;
  hubPin: HubPin;
  devicePublic: ReturnType<typeof publicDeviceKey>;
}

/**
 * Receiver side (local unlock required): create W, write blob, seal W to hub,
 * pin hub pubs outside the vault, zero W. Pure aside from disk writes under base.
 */
export function prepareReceiverEnroll(input: ReceiverEnrollInput): ReceiverEnrollResult {
  const identity = input.vault.syncIdentity;
  if (!identity) {
    throw new EnrollError("this vault has no sync identity — pair first (abra sync pair)");
  }

  const hub = findPeer(input.vault, input.hubNameOrId);
  if (!hub) {
    throw new EnrollError(`no paired peer named "${input.hubNameOrId}" — see: abra sync peers`);
  }
  if (hub.peer.role !== "source") {
    throw new EnrollError(
      `peer "${hub.peer.name}" is paired as ${hub.peer.role} — enroll seals to the hub (source)`,
    );
  }

  const { key: deviceKey } =
    input.deviceKey !== undefined
      ? { key: input.deviceKey }
      : getOrCreateDeviceKey({ base: input.base, now: input.now });
  const devicePublic = publicDeviceKey(deviceKey);

  const hubPin = setHubPin(
    {
      deviceId: hub.id,
      ed25519: hub.peer.ed25519,
      x25519: hub.peer.x25519,
      pinnedAt: input.now,
    },
    { base: input.base },
  );

  const wrapKey = generateWrapKey();
  let offer: EnrollOffer;
  let blob: UnlockBlobFile;
  try {
    blob = createAndWriteUnlockBlob(input.masterKey, wrapKey, deviceKey.id, {
      base: input.base,
    });
    offer = sealWrapKeyForHub({
      sender: identity,
      hub: { id: hub.id, x25519: hub.peer.x25519 },
      wrapKey,
      deviceId: deviceKey.id,
      deviceEd25519: deviceKey.ed25519.publicKey,
      deviceX25519: deviceKey.x25519.publicKey,
      masterKeyFingerprint: blob.masterKeyFingerprint,
      now: input.now,
    });
  } finally {
    wrapKey.fill(0);
  }

  return { offer, blob, hubPin, devicePublic };
}

/**
 * Pure: apply an enroll offer onto the hub vault. Only paired peers with role
 * **receiver** may enroll. Caller authenticates (Touch ID) *before* updateVault.
 */
export function planHubEnroll(
  vault: Vault,
  offerRaw: unknown,
  opts: { now?: number } = {},
): { vault: Vault; peerId: string; peerName: string; unlockWrap: UnlockWrap } {
  const identity = vault.syncIdentity;
  if (!identity) {
    throw new EnrollError("this vault has no sync identity — pair first (abra sync pair)");
  }

  const offer = parseEnrollOffer(offerRaw);
  if (offer.to !== identity.id) {
    throw new EnrollError("enroll offer is addressed to another hub identity");
  }

  const found = findPeer(vault, offer.from);
  if (!found) {
    throw new EnrollError("enroll offer sender is not a paired peer");
  }
  if (found.peer.role !== "receiver") {
    throw new EnrollError(
      `peer "${found.peer.name}" is paired as ${found.peer.role} — only receivers can enroll for remote unlock`,
    );
  }

  assertValidPublicKeys(offer.deviceEd25519, offer.deviceX25519);
  if (!isUuid(offer.deviceId)) throw new EnrollError("enroll offer deviceId must be a UUID");

  const wrapKey = openWrapKeyFromOffer(offer, identity, found.peer.ed25519);
  let unlockWrap: UnlockWrap;
  try {
    unlockWrap = {
      v: 1,
      wrapKey: encodeWrapKey(wrapKey),
      deviceId: offer.deviceId,
      deviceEd25519: offer.deviceEd25519,
      deviceX25519: offer.deviceX25519,
      masterKeyFingerprint: offer.masterKeyFingerprint,
      enrolledAt: opts.now ?? offer.createdAt,
    };
  } finally {
    wrapKey.fill(0);
  }

  const peers = { ...(vault.syncPeers ?? {}) };
  peers[found.id] = { ...found.peer, unlockWrap };

  return {
    vault: { ...vault, syncPeers: peers },
    peerId: found.id,
    peerName: found.peer.name,
    unlockWrap,
  };
}

/** Clear unlockWrap on a peer (used by revoke; unpair deletes the whole peer). */
export function clearPeerUnlockWrap(
  vault: Vault,
  nameOrId: string,
): { vault: Vault; cleared: boolean; peerId?: string; peerName?: string } {
  const found = findPeer(vault, nameOrId);
  if (!found) throw new EnrollError(`no paired peer named "${nameOrId}" — see: abra sync peers`);
  if (!found.peer.unlockWrap) {
    return { vault, cleared: false, peerId: found.id, peerName: found.peer.name };
  }
  const { unlockWrap: _drop, ...rest } = found.peer;
  const peers = { ...(vault.syncPeers ?? {}), [found.id]: rest };
  return { vault: { ...vault, syncPeers: peers }, cleared: true, peerId: found.id, peerName: found.peer.name };
}

export interface EnrollHubDeps {
  authenticate: (reason: string) => Promise<void>;
  loadVault: () => Promise<Vault>;
  updateVault: (mutator: VaultMutator) => Promise<Vault>;
  now?: () => number;
  log?: (line: string) => void;
}

/**
 * Hub: Touch ID, then store unlockWrap from a verified offer.
 * Does not hold the vault lock across authenticate.
 */
export async function completeHubEnroll(
  offer: unknown,
  peerNameOrId: string,
  deps: EnrollHubDeps,
): Promise<{ peerId: string; peerName: string }> {
  const before = await deps.loadVault();
  const found = findPeer(before, peerNameOrId);
  if (!found) throw new EnrollError(`no paired peer named "${peerNameOrId}" — see: abra sync peers`);
  if (found.peer.role !== "receiver") {
    throw new EnrollError(
      `peer "${found.peer.name}" is paired as ${found.peer.role} — only receivers can enroll`,
    );
  }

  const offerParsed = parseEnrollOffer(offer);
  if (offerParsed.from !== found.id) {
    throw new EnrollError(
      `enroll offer is from a different peer than "${found.peer.name}"`,
    );
  }

  await deps.authenticate(`abracadabra: enroll remote unlock for ${found.peer.name}`);

  let peerId = found.id;
  let peerName = found.peer.name;
  await deps.updateVault((fresh) => {
    const plan = planHubEnroll(fresh, offer, { now: deps.now?.() });
    if (plan.peerId !== found.id) {
      throw new EnrollError("peer changed during enroll — refuse");
    }
    peerId = plan.peerId;
    peerName = plan.peerName;
    return plan.vault;
  });

  return { peerId, peerName };
}

export interface EnrollLoopbackReceiver {
  vault: Vault;
  masterKey: Buffer;
  base: string;
  /** How this receiver names the hub (source peer). */
  hubNameOrId: string;
}

export interface EnrollLoopbackHub {
  vault: Vault;
  /** How the hub names the receiver. */
  peerNameOrId: string;
}

/**
 * In-process enroll (PR 2 test harness). No network — prepares on the receiver,
 * then applies on the hub. Mimics the future wire handshake.
 */
export function enrollLoopback(
  hub: EnrollLoopbackHub,
  receiver: EnrollLoopbackReceiver,
  opts: { now?: number } = {},
): {
  hubVault: Vault;
  offer: EnrollOffer;
  blob: UnlockBlobFile;
  peerId: string;
  peerName: string;
} {
  const prepared = prepareReceiverEnroll({
    vault: receiver.vault,
    masterKey: receiver.masterKey,
    base: receiver.base,
    hubNameOrId: receiver.hubNameOrId,
    now: opts.now,
  });

  // Sanity: offer must target this hub's identity.
  const hubId = hub.vault.syncIdentity?.id;
  if (!hubId || prepared.offer.to !== hubId) {
    throw new EnrollError("loopback enroll: offer not addressed to hub identity");
  }

  const found = findPeer(hub.vault, hub.peerNameOrId);
  if (!found) throw new EnrollError(`loopback enroll: hub has no peer "${hub.peerNameOrId}"`);
  if (prepared.offer.from !== found.id) {
    throw new EnrollError("loopback enroll: receiver identity does not match hub peer record");
  }

  const plan = planHubEnroll(hub.vault, prepared.offer, { now: opts.now });
  return {
    hubVault: plan.vault,
    offer: prepared.offer,
    blob: prepared.blob,
    peerId: plan.peerId,
    peerName: plan.peerName,
  };
}

/** Re-export fingerprint helper for callers that need to detect re-enroll. */
export { masterKeyFingerprint };
export type { UnlockBlobFile, SyncIdentity };
