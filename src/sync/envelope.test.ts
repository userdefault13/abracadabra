import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import type { Vault } from "../core/vault.js";
import { ed25519PrivateKey, generateSyncIdentity } from "./identity.js";
import {
  EnvelopeError,
  MAX_CLOCK_SKEW_MS,
  openEnvelope,
  parseEnvelope,
  sealForPeer,
  sealProjects,
  sigMessage,
  trustFromVault,
  verifyEnvelope,
  type SealedEnvelope,
} from "./envelope.js";
import { makePair, peerRecord } from "../../test/fixtures/sync-vaults.js";

const NOW = 1_800_000_000_000;

function reasonOf(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    if (err instanceof EnvelopeError) return err.reason;
    throw err;
  }
  return "ok";
}

function flipB64(b64: string, at = 0): string {
  const buf = Buffer.from(b64, "base64");
  buf[at] ^= 0x01;
  return buf.toString("base64");
}

/** Re-sign an edited header with `signer` (models a malicious but paired source). */
function resign(env: SealedEnvelope, signer = makePair().sourceId): SealedEnvelope {
  const sig = crypto.sign(null, sigMessage(env, Buffer.from(env.ct, "base64")), ed25519PrivateKey(signer));
  return { ...env, sig: sig.toString("base64") };
}

describe("sealed envelope (abra-sync-seal-v1)", () => {
  it("round-trips: source seals named projects to the receiver, receiver verifies + opens", () => {
    const { source, receiver, sourceId, receiverId } = makePair();
    const env = sealForPeer(source, "mini", ["app"], { now: NOW });
    expect(env).toMatchObject({ v: 1, from: sourceId.id, to: receiverId.id, projects: ["app"], createdAt: NOW });
    expect(Object.keys(env).sort()).toEqual(
      ["bundleId", "createdAt", "ct", "epk", "from", "nonce", "projects", "sig", "to", "v"],
    );
    const wire = JSON.stringify(env);
    expect(wire).not.toContain("a-from-source");
    expect(wire).not.toContain(sourceId.ed25519.privateKey);

    const parsed = parseEnvelope(JSON.parse(wire));
    const who = verifyEnvelope(parsed, trustFromVault(receiver)!, { now: NOW, checkFreshness: true });
    expect(who).toEqual({ peerId: sourceId.id, peerName: "mbp" });
    const projects = openEnvelope(parsed, receiver.syncIdentity!);
    expect(projects).toEqual({ app: source.projects.app });
  });

  it("fresh ephemeral key, nonce and bundle id per seal", () => {
    const { source } = makePair();
    const a = sealForPeer(source, "mini", ["app"]);
    const b = sealForPeer(source, "mini", ["app"]);
    expect(a.epk).not.toBe(b.epk);
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.bundleId).not.toBe(b.bundleId);
  });

  it("sealForPeer: receivers only, known projects only, no reserved names", () => {
    const { source, receiver } = makePair();
    expect(() => sealForPeer(receiver, "mbp", ["app"])).toThrow(/source for this machine/);
    expect(() => sealForPeer(source, "nope", ["app"])).toThrow(/no paired peer/);
    expect(() => sealForPeer(source, "mini", ["missing"])).toThrow(/unknown project/);
    const withTreasury: Vault = {
      ...source,
      projects: { ...source.projects, __abra_treasury__: { createdAt: 1, vars: {} } },
    };
    expect(() => sealForPeer(withTreasury, "mini", ["__abra_treasury__"])).toThrow(/reserved/);
    expect(() => sealForPeer({ ...source, syncIdentity: undefined }, "mini", ["app"])).toThrow(/no sync identity/);
  });

  it("tampered ciphertext or header fails the signature", () => {
    const { source, receiver } = makePair();
    const trust = trustFromVault(receiver)!;
    const env = sealForPeer(source, "mini", ["app", "other"], { now: NOW });
    const v = (e: SealedEnvelope) => reasonOf(() => verifyEnvelope(e, trust, { now: NOW, checkFreshness: true }));
    expect(v(env)).toBe("ok");
    expect(v({ ...env, ct: flipB64(env.ct, 3) })).toBe("bad-signature");
    expect(v({ ...env, createdAt: env.createdAt + 1 })).toBe("bad-signature");
    expect(v({ ...env, projects: ["app"] })).toBe("bad-signature");
    expect(v({ ...env, bundleId: crypto.randomUUID() })).toBe("bad-signature");
    expect(v({ ...env, nonce: flipB64(env.nonce) })).toBe("bad-signature");
    expect(v({ ...env, sig: flipB64(env.sig, 10) })).toBe("bad-signature");
    const otherEpk = sealForPeer(source, "mini", ["app"]).epk;
    expect(v({ ...env, epk: otherEpk })).toBe("bad-signature");
  });

  it("header edits re-signed by the source still fail decryption (GCM binds the header)", () => {
    const { source, receiver, sourceId } = makePair();
    const env = sealForPeer(source, "mini", ["app"], { now: NOW });
    const edited = resign({ ...env, createdAt: env.createdAt + 5 }, sourceId);
    expect(reasonOf(() => verifyEnvelope(edited, trustFromVault(receiver)!))).toBe("ok");
    expect(reasonOf(() => openEnvelope(edited, receiver.syncIdentity!))).toBe("decrypt-failed");
  });

  it("wrong recipient: addressed elsewhere, or opened with another identity", () => {
    const { source, receiver, sourceId } = makePair();
    const stranger = generateSyncIdentity();
    const env = sealProjects(sourceId, { id: stranger.id, x25519: stranger.x25519.publicKey }, {
      app: source.projects.app,
    });
    expect(reasonOf(() => verifyEnvelope(env, trustFromVault(receiver)!))).toBe("wrong-recipient");
    const mine = sealForPeer(source, "mini", ["app"]);
    expect(reasonOf(() => openEnvelope(mine, { ...stranger, id: mine.to }))).toBe("decrypt-failed");
  });

  it("wrong sender key: an impostor claiming the source's id is rejected", () => {
    const { source, receiver, sourceId, receiverId } = makePair();
    const impostor = { ...generateSyncIdentity(), id: sourceId.id };
    const env = sealProjects(impostor, { id: receiverId.id, x25519: receiverId.x25519.publicKey }, {
      app: source.projects.app,
    });
    expect(reasonOf(() => verifyEnvelope(env, trustFromVault(receiver)!))).toBe("bad-signature");
  });

  it("unknown sender and a sender this vault considers a receiver are rejected", () => {
    const { source, receiver, sourceId } = makePair();
    const env = sealForPeer(source, "mini", ["app"]);
    expect(reasonOf(() => verifyEnvelope(env, { myId: env.to, peers: {} }))).toBe("unknown-sender");
    const asReceiver: Vault = { ...receiver, syncPeers: { [sourceId.id]: peerRecord(sourceId, "mbp", "receiver") } };
    expect(reasonOf(() => verifyEnvelope(env, trustFromVault(asReceiver)!))).toBe("sender-not-source");
  });

  it("stale / future createdAt and replays are rejected at receive time", () => {
    const { source, receiver } = makePair();
    const trust = trustFromVault(receiver)!;
    const env = sealForPeer(source, "mini", ["app"], { now: NOW });
    const at = (now: number) => reasonOf(() => verifyEnvelope(env, trust, { now, checkFreshness: true }));
    expect(at(NOW + MAX_CLOCK_SKEW_MS)).toBe("ok");
    expect(at(NOW + MAX_CLOCK_SKEW_MS + 1)).toBe("stale");
    expect(at(NOW - MAX_CLOCK_SKEW_MS - 1)).toBe("stale");
    expect(reasonOf(() => verifyEnvelope(env, trust, { now: NOW + 3_600_000 }))).toBe("ok"); // queued apply
    expect(reasonOf(() => verifyEnvelope(env, trust, { isReplay: (id) => id === env.bundleId }))).toBe("replay");
  });

  it("reserved / duplicate project names in a correctly signed header are rejected", () => {
    const { source, receiver, sourceId } = makePair();
    const trust = trustFromVault(receiver)!;
    const env = sealForPeer(source, "mini", ["app"]);
    for (const projects of [["__abra_treasury__"], ["app", "app"], [" app"], ["__proto__"], []]) {
      expect(reasonOf(() => verifyEnvelope(resign({ ...env, projects }, sourceId), trust))).toBe("bad-projects");
    }
  });

  it("parseEnvelope is strict about shape", () => {
    const { source } = makePair();
    const env = sealForPeer(source, "mini", ["app"]);
    const bad = (o: unknown) => reasonOf(() => parseEnvelope(o));
    expect(bad(env)).toBe("ok");
    expect(bad(null)).toBe("malformed");
    expect(bad({ ...env, extra: 1 })).toBe("malformed");
    expect(bad({ ...env, v: 2 })).toBe("malformed");
    expect(bad({ ...env, from: "not-a-uuid" })).toBe("malformed");
    expect(bad({ ...env, epk: env.epk.slice(4) })).toBe("malformed");
    expect(bad({ ...env, sig: `${env.sig}AA==` })).toBe("malformed");
    expect(bad({ ...env, ct: "" })).toBe("malformed");
    expect(bad({ ...env, createdAt: "1" })).toBe("malformed");
    expect(bad({ ...env, projects: [1] })).toBe("malformed");
    // full-vault bundles (backup format) are not envelopes
    expect(bad({ format: "abracadabra-backup", version: 1, data: "x" })).toBe("malformed");
  });
});
