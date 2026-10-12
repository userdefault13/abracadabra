import { describe, it, expect, afterEach, vi } from "vitest";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import type { Vault } from "../core/vault.js";
import {
  decryptVault,
  encryptVault,
  encryptVaultForExport,
  loadVault,
  saveVault,
  withoutDeviceLocal,
  writeRestoredVault,
} from "../core/vault.js";
import { openAnyBundle, openBundle, sealBundle, sealScopedBundle } from "../core/backup.js";
import { extractScopedProjects, mergeScopedProjects, validateScope } from "../core/sync-scope.js";
import { loadSyncState, saveSyncState, threeWayMerge } from "../core/sync.js";
import { syncStateFile, vaultFile } from "../core/paths.js";
import * as platform from "../platform/index.js";
import { setDefaultKdfForTests } from "../platform/master-key-file.js";
import { generateSyncIdentity, getOrCreateSyncIdentity } from "./identity.js";
import { planPeerUpsert } from "./peers.js";
import { anchorsFile, anchorsFromVault, writeAnchors } from "../core/sync-inbox-store.js";

vi.mock("../platform/index.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../platform/index.js")>();
  return { ...actual, authenticate: vi.fn(async () => {}) };
});

const hasOpenssl = spawnSync("openssl", ["version"], { stdio: "ignore" }).status === 0;
const PASS = "device-local-test-passphrase";

function entry(value: string) {
  return { value, secret: true, updatedAt: 1 };
}

/** A vault with projects + a sync identity + one paired peer + accept policy + inbox settings. */
function pairedVault(projects: Vault["projects"]): Vault {
  const base: Vault = { version: 1, projects, connections: {}, passkeys: [], apiKeys: {} };
  const withId = getOrCreateSyncIdentity(base).vault;
  const peer = generateSyncIdentity();
  const paired = planPeerUpsert(withId, {
    id: peer.id,
    name: "mini",
    ed25519: peer.ed25519.publicKey,
    x25519: peer.x25519.publicKey,
    role: "receiver",
  }).vault;
  return {
    ...paired,
    syncAccept: [{ from: "*", projects: "*", auto: true }],
    syncInbox: { enabled: true, port: 7333, bind: "100.64.0.1" },
  };
}

function expectNoIdentityMaterial(text: string, v: Vault) {
  expect(text).not.toContain("syncIdentity");
  expect(text).not.toContain("syncPeers");
  expect(text).not.toContain("syncAccept");
  expect(text).not.toContain("syncInbox");
  expect(text).not.toContain(v.syncIdentity!.ed25519.privateKey);
  expect(text).not.toContain(v.syncIdentity!.x25519.privateKey);
}

const envBackup = { ...process.env };
let tmp = "";

function useTempDir(): string {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "abra-dl-"));
  process.env.ABRA_DIR = tmp;
  return tmp;
}

async function setupTempVault(v: Vault): Promise<Buffer> {
  useTempDir();
  process.env.ABRA_AGENT = "0";
  process.env.ABRA_KEYSTORE = "passphrase-file";
  process.env.ABRA_SKIP_BIOMETRICS = "1";
  process.env.ABRA_AUTH = "none";
  process.env.ABRA_HEADLESS_PASSPHRASE = PASS;
  setDefaultKdfForTests({ N: 16384 });
  platform.resetPlatformForTests();
  const masterKey = crypto.randomBytes(32);
  await platform.restoreMasterKey(masterKey, PASS);
  await saveVault(v);
  return masterKey;
}

afterEach(async () => {
  const { stopLanHost } = await import("../usb/lan-host.js");
  await stopLanHost();
  process.env = { ...envBackup };
  setDefaultKdfForTests(null);
  platform.resetPlatformForTests();
  if (tmp) fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 3 });
  tmp = "";
});

describe("device-local vault fields (syncIdentity / syncPeers)", () => {
  it("scoped bundles carry only projects — never identity or peers", () => {
    useTempDir();
    const v = pairedVault({ app: { createdAt: 1, vars: { K: entry("v") } } });
    const scope = validateScope(v, ["app"]);
    const bundle = sealScopedBundle(extractScopedProjects(v, scope), scope, "pin-123456");
    const opened = openAnyBundle(bundle, "pin-123456");
    expect(opened.kind).toBe("scoped");
    expectNoIdentityMaterial(JSON.stringify(opened.payload), v);
  });

  it("full-vault merge keeps OUR identity/peers and never takes the peer's", () => {
    const ours = pairedVault({ a: { createdAt: 1, vars: { K: entry("1") } } });
    const theirs = pairedVault({ b: { createdAt: 1, vars: { K: entry("2") } } });
    const { merged } = threeWayMerge(ours, theirs, null, new Map(), "LAN peer");
    expect(merged.syncIdentity).toEqual(ours.syncIdentity);
    expect(merged.syncPeers).toEqual(ours.syncPeers);
    expect(merged.syncAccept).toEqual(ours.syncAccept);
    expect(merged.syncInbox).toEqual(ours.syncInbox);
    expect(Object.keys(merged.projects).sort()).toEqual(["a", "b"]);

    const bare: Vault = { version: 1, projects: {} };
    const fromBare = threeWayMerge(bare, theirs, null, new Map(), "USB").merged;
    expect(fromBare.syncIdentity).toBeUndefined();
    expect(fromBare.syncPeers).toBeUndefined();
    expect(fromBare.syncAccept).toBeUndefined();
    expect(fromBare.syncInbox).toBeUndefined();
  });

  it("scoped merge keeps local identity/peers/policy/inbox", () => {
    const local = pairedVault({});
    const { merged } = mergeScopedProjects(local, { app: { createdAt: 1, vars: { K: entry("x") } } });
    expect(merged.syncIdentity).toEqual(local.syncIdentity);
    expect(merged.syncPeers).toEqual(local.syncPeers);
    expect(merged.syncAccept).toEqual(local.syncAccept);
    expect(merged.syncInbox).toEqual(local.syncInbox);
    expect(merged.projects.app).toBeDefined();
  });

  it("export encryption strips identity/peers; local encryption keeps them", () => {
    const v = pairedVault({ a: { createdAt: 1, vars: {} } });
    const key = crypto.randomBytes(32);
    const exported = decryptVault(encryptVaultForExport(v, key), key);
    expectNoIdentityMaterial(JSON.stringify(exported), v);
    expect(exported.projects.a).toBeDefined();
    expect(decryptVault(encryptVault(v, key), key).syncIdentity).toEqual(v.syncIdentity);
    expect(withoutDeviceLocal(v)).not.toHaveProperty("syncIdentity");
    expect(v.syncIdentity).toBeDefined(); // not mutated
  });

  it("restore drops identity/peers/policy/inbox and the inbox trust mirror (cloned vaults must re-pair)", () => {
    const dir = useTempDir();
    const v = pairedVault({ a: { createdAt: 1, vars: { K: entry("1") } } });
    writeAnchors(dir, anchorsFromVault(v));
    expect(fs.existsSync(anchorsFile(dir))).toBe(true);
    const key = crypto.randomBytes(32);
    const res = writeRestoredVault(v, key);
    expect(res.droppedSyncPairing).toBe(true);
    expect(fs.existsSync(anchorsFile(dir))).toBe(false);
    const restored = decryptVault(JSON.parse(fs.readFileSync(vaultFile(), "utf8")), key);
    expect(restored.syncIdentity).toBeUndefined();
    expect(restored.syncPeers).toBeUndefined();
    expect(restored.syncAccept).toBeUndefined();
    expect(restored.syncInbox).toBeUndefined();
    expect(restored.projects.a.vars.K.value).toBe("1");
    expect(writeRestoredVault({ version: 1, projects: {} }, key).droppedSyncPairing).toBe(false);
  });

  it("sync-state bases never store identity/peers", async () => {
    const v = pairedVault({ a: { createdAt: 1, vars: {} } });
    await setupTempVault(v);
    await saveSyncState("lan:peer", v);
    const base = (await loadSyncState("lan:peer"))!.base;
    expect(base.syncIdentity).toBeUndefined();
    expect(base.syncPeers).toBeUndefined();
    expect(base.syncAccept).toBeUndefined();
    expect(base.syncInbox).toBeUndefined();
    expect(base.projects.a).toBeDefined();
    expect(fs.existsSync(syncStateFile())).toBe(true);
  });

  it.skipIf(!hasOpenssl)(
    "LAN host: pulled full bundle omits host identity; a peer push never replaces it",
    async () => {
      const hostVault = pairedVault({ keep: { createdAt: 1, vars: { A: entry("a") } } });
      await setupTempVault(hostVault);
      const { startLanHost } = await import("../usb/lan-host.js");
      const host = await startLanHost({ advertise: false, port: 0, ttlMs: 60_000, allowDeletes: true });

      const post = (p: string, body: unknown) =>
        new Promise<{ status: number; json: any }>((resolve, reject) => {
          const data = JSON.stringify(body);
          const req = https.request(
            {
              host: "127.0.0.1",
              port: host.port,
              path: p,
              method: "POST",
              rejectUnauthorized: false,
              headers: {
                Authorization: `Bearer ${host.pin}`,
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(data),
              },
            },
            (res) => {
              const chunks: Buffer[] = [];
              res.on("data", (c) => chunks.push(c));
              res.on("end", () =>
                resolve({ status: res.statusCode ?? 0, json: JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") }),
              );
            },
          );
          req.on("error", reject);
          req.end(data);
        });

      const pulled = await post("/lan/pull", {});
      expect(pulled.status).toBe(200);
      const payload = openBundle(pulled.json.bundle, host.pin);
      const remote = decryptVault(
        { format: "abracadabra-vault", version: 1, ...payload.vaultEnc },
        Buffer.from(payload.masterKey, "base64"),
      );
      expectNoIdentityMaterial(JSON.stringify(remote), hostVault);

      // An older peer pushes a vault that includes ITS OWN identity + peers.
      const peerVault: Vault = {
        ...pairedVault({ keep: { createdAt: 1, vars: { A: entry("b") } } }),
        syncAccept: [],
        syncInbox: { enabled: false, port: 1 },
      };
      const peerKey = crypto.randomBytes(32);
      const pushed = await post("/lan/push", {
        bundle: sealBundle(encryptVault(peerVault, peerKey), peerKey, host.pin),
      });
      expect(pushed.status).toBe(200);
      const after = await loadVault();
      expect(after.projects.keep.vars.A.value).toBe("b");
      expect(after.syncIdentity).toEqual(hostVault.syncIdentity);
      expect(after.syncPeers).toEqual(hostVault.syncPeers);
      expect(after.syncAccept).toEqual(hostVault.syncAccept);
      expect(after.syncInbox).toEqual(hostVault.syncInbox);
    },
    20_000,
  );
});
