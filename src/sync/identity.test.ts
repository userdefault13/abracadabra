import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import type { Vault } from "../core/vault.js";
import {
  decodeRawKey,
  generateSyncIdentity,
  getOrCreateSyncIdentity,
  identityFingerprint,
  publicIdentity,
} from "./identity.js";
import { SAS_WORDS } from "./wordlist.js";
import {
  PAIR_PROTOCOL,
  safetyCode,
  signTranscript,
  transcriptHash,
  verifyTranscript,
  type TranscriptInput,
} from "./sas.js";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FP_RE = /^[0-9a-f]{4}( [0-9a-f]{4}){7}$/;

function emptyVault(): Vault {
  return { version: 1, projects: {}, connections: {} };
}

describe("sync identity", () => {
  it("generates uuid + raw 32-byte base64 Ed25519/X25519 keys", () => {
    const id = generateSyncIdentity(42);
    expect(id.id).toMatch(UUID_RE);
    expect(id.createdAt).toBe(42);
    for (const k of [id.ed25519.publicKey, id.ed25519.privateKey, id.x25519.publicKey, id.x25519.privateKey]) {
      expect(decodeRawKey(k)).toHaveLength(32);
    }
    expect(id.ed25519.publicKey).not.toBe(id.x25519.publicKey);
    expect(generateSyncIdentity().id).not.toBe(id.id);
  });

  it("getOrCreateSyncIdentity is pure and idempotent", () => {
    const v = emptyVault();
    const first = getOrCreateSyncIdentity(v, { now: 7 });
    expect(first.created).toBe(true);
    expect(v.syncIdentity).toBeUndefined(); // input untouched
    expect(first.vault.syncIdentity).toEqual(first.identity);

    const again = getOrCreateSyncIdentity(first.vault);
    expect(again.created).toBe(false);
    expect(again.vault).toBe(first.vault);
    expect(again.identity).toEqual(first.identity);
  });

  it("refuses to silently replace a malformed identity", () => {
    const v = { ...emptyVault(), syncIdentity: { id: "nope" } } as unknown as Vault;
    expect(() => getOrCreateSyncIdentity(v)).toThrow(/malformed/);
  });

  it("fingerprint: 8 groups of 4 hex, deterministic, key-sensitive", () => {
    const a = generateSyncIdentity();
    const b = generateSyncIdentity();
    const fa = identityFingerprint(a.ed25519.publicKey, a.x25519.publicKey);
    expect(fa).toMatch(FP_RE);
    expect(identityFingerprint(a.ed25519.publicKey, a.x25519.publicKey)).toBe(fa);
    expect(identityFingerprint(b.ed25519.publicKey, a.x25519.publicKey)).not.toBe(fa);
    expect(identityFingerprint(a.ed25519.publicKey, b.x25519.publicKey)).not.toBe(fa);
    // Domain separated: not just sha256 of the concatenated keys.
    const naive = crypto
      .createHash("sha256")
      .update(Buffer.concat([decodeRawKey(a.ed25519.publicKey), decodeRawKey(a.x25519.publicKey)]))
      .digest("hex")
      .slice(0, 32);
    expect(fa.replace(/ /g, "")).not.toBe(naive);
  });

  it("publicIdentity never carries private keys", () => {
    const a = generateSyncIdentity();
    const pub = publicIdentity(a);
    const text = JSON.stringify(pub);
    expect(text).not.toContain(a.ed25519.privateKey);
    expect(text).not.toContain(a.x25519.privateKey);
  });

  it("decodeRawKey rejects wrong lengths and non-canonical base64", () => {
    expect(() => decodeRawKey(Buffer.alloc(31).toString("base64"))).toThrow();
    expect(() => decodeRawKey("not base64!!")).toThrow();
  });
});

describe("SAS wordlist", () => {
  it("has exactly 256 unique lowercase words", () => {
    expect(SAS_WORDS).toHaveLength(256);
    expect(new Set(SAS_WORDS).size).toBe(256);
    for (const w of SAS_WORDS) expect(w).toMatch(/^[a-z]+$/);
  });
});

function transcriptInput(): TranscriptInput {
  const a = generateSyncIdentity();
  const b = generateSyncIdentity();
  const nonce = () => crypto.randomBytes(32).toString("base64");
  return {
    tlsFingerprint: Array.from(crypto.randomBytes(32), (x) => x.toString(16).padStart(2, "0").toUpperCase()).join(":"),
    listener: {
      protocol: PAIR_PROTOCOL,
      id: a.id,
      name: "mbp",
      ed25519: a.ed25519.publicKey,
      x25519: a.x25519.publicKey,
      nonce: nonce(),
      role: "source",
    },
    connector: {
      protocol: PAIR_PROTOCOL,
      id: b.id,
      name: "mini",
      ed25519: b.ed25519.publicKey,
      x25519: b.x25519.publicKey,
      nonce: nonce(),
      role: "receiver",
    },
  };
}

describe("transcript + safety code", () => {
  it("is identical on both ends (fingerprint formatting does not matter)", () => {
    const input = transcriptInput();
    const listenerView = transcriptHash(input);
    const connectorView = transcriptHash({
      ...structuredClone(input),
      tlsFingerprint: input.tlsFingerprint.replace(/:/g, "").toLowerCase(),
    });
    expect(connectorView.equals(listenerView)).toBe(true);
    const code = safetyCode(listenerView);
    expect(safetyCode(connectorView)).toEqual(code);
    expect(code.words).toHaveLength(6);
    for (const w of code.words) expect(SAS_WORDS).toContain(w);
    expect(code.digits).toMatch(/^\d{3} \d{3} \d{3} \d{3}$/);
  });

  it("changes when any transcript input changes", () => {
    const input = transcriptInput();
    const base = transcriptHash(input).toString("hex");
    const other = generateSyncIdentity();
    const mutations: ((i: TranscriptInput) => void)[] = [
      (i) => (i.tlsFingerprint = "00".repeat(32)),
      (i) => (i.listener.ed25519 = other.ed25519.publicKey),
      (i) => (i.listener.x25519 = other.x25519.publicKey),
      (i) => (i.connector.ed25519 = other.ed25519.publicKey),
      (i) => (i.connector.x25519 = other.x25519.publicKey),
      (i) => (i.listener.nonce = crypto.randomBytes(32).toString("base64")),
      (i) => (i.connector.nonce = crypto.randomBytes(32).toString("base64")),
      (i) => {
        i.listener.role = "receiver";
        i.connector.role = "source";
      },
      (i) => (i.listener.id = other.id),
      (i) => (i.connector.name = "evil"),
      // swapping sides must not collide
      (i) => {
        const l = i.listener;
        i.listener = { ...i.connector, role: l.role };
        i.connector = { ...l, role: i.connector.role };
      },
    ];
    const seen = new Set([base]);
    for (const mutate of mutations) {
      const copy = structuredClone(input);
      mutate(copy);
      const h = transcriptHash(copy).toString("hex");
      expect(seen.has(h)).toBe(false);
      seen.add(h);
    }
  });

  it("safety code is domain separated from the raw transcript", () => {
    const t = transcriptHash(transcriptInput());
    const naiveWords = [...t.subarray(0, 6)].map((b) => SAS_WORDS[b]);
    expect(safetyCode(t).words).not.toEqual(naiveWords);
  });
});

describe("transcript signatures", () => {
  it("verifies the signer and rejects a swapped public key", () => {
    const input = transcriptInput();
    const a = generateSyncIdentity();
    input.listener.ed25519 = a.ed25519.publicKey;
    input.listener.x25519 = a.x25519.publicKey;
    const t = transcriptHash(input);
    const sig = signTranscript(a, "listener", t);
    expect(verifyTranscript(a.ed25519.publicKey, "listener", t, sig)).toBe(true);

    // Attacker swaps in their key: neither the original sig nor the new transcript verifies.
    const mallory = generateSyncIdentity();
    expect(verifyTranscript(mallory.ed25519.publicKey, "listener", t, sig)).toBe(false);
    const swapped = transcriptHash({ ...input, listener: { ...input.listener, ed25519: mallory.ed25519.publicKey } });
    expect(verifyTranscript(mallory.ed25519.publicKey, "listener", swapped, sig)).toBe(false);
  });

  it("binds the side label (a listener signature is not a connector signature)", () => {
    const a = generateSyncIdentity();
    const t = transcriptHash(transcriptInput());
    const sig = signTranscript(a, "listener", t);
    expect(verifyTranscript(a.ed25519.publicKey, "connector", t, sig)).toBe(false);
  });

  it("rejects garbage signatures without throwing", () => {
    const a = generateSyncIdentity();
    const t = transcriptHash(transcriptInput());
    expect(verifyTranscript(a.ed25519.publicKey, "listener", t, "AAAA")).toBe(false);
    expect(verifyTranscript("bad", "listener", t, Buffer.alloc(64).toString("base64"))).toBe(false);
  });
});
