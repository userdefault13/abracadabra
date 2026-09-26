import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import type { Vault, VarEntry } from "./vault.js";
import { saveVault, loadVault, encryptVault } from "./vault.js";
import { sealBundle, openBundle, readBundleFile } from "./backup.js";
import {
  threeWayMerge,
  loadSyncState,
  saveSyncState,
  usbPeerId,
  lanPeerId,
  formatProjectDeletionLines,
} from "./sync.js";
import { vaultFile, syncStateFile, abraDir } from "./paths.js";
import { getOrCreateDeviceId } from "./device-id.js";
import { assertUsbPassphrase, USB_PASSPHRASE_MIN } from "./passphrase.js";
import * as platform from "../platform/index.js";
import { setDefaultKdfForTests } from "../platform/master-key-file.js";

const skipWin = process.platform === "win32";

vi.mock("../platform/index.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../platform/index.js")>();
  return {
    ...actual,
    authenticate: vi.fn(async () => {}),
  };
});

function entry(value: string, updatedAt = 1): VarEntry {
  return { value, secret: true, updatedAt };
}

function vault(projects: Vault["projects"]): Vault {
  return { version: 1, projects, connections: {}, passkeys: [], apiKeys: {} };
}

async function setupTempVault(v: Vault): Promise<{ tmp: string; masterKey: Buffer }> {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "abra-harden-"));
  process.env.ABRA_DIR = tmp;
  process.env.ABRA_AGENT = "0";
  process.env.ABRA_KEYSTORE = "passphrase-file";
  process.env.ABRA_SKIP_BIOMETRICS = "1";
  process.env.ABRA_AUTH = "none";
  process.env.ABRA_HEADLESS_PASSPHRASE = "harden-test-passphrase-ok";
  setDefaultKdfForTests({ N: 16384 });
  platform.resetPlatformForTests();
  const masterKey = crypto.randomBytes(32);
  await platform.restoreMasterKey(masterKey, "harden-test-passphrase-ok");
  await platform.getMasterKey();
  await saveVault(v);
  return { tmp, masterKey };
}

function cleanupTemp(tmp: string, envBackup: NodeJS.ProcessEnv) {
  process.env = { ...envBackup };
  setDefaultKdfForTests(null);
  platform.resetPlatformForTests();
  fs.rmSync(tmp, { recursive: true, force: true });
}

function snapshotBytes(dir: string): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  const walk = (d: string, prefix = "") => {
    if (!fs.existsSync(d)) return;
    for (const name of fs.readdirSync(d)) {
      const full = path.join(d, name);
      const rel = prefix ? `${prefix}/${name}` : name;
      const st = fs.statSync(full);
      if (st.isDirectory()) walk(full, rel);
      else out.set(rel, fs.readFileSync(full));
    }
  };
  walk(dir);
  return out;
}

function expectMapsEqual(a: Map<string, Buffer>, b: Map<string, Buffer>) {
  expect([...a.keys()].sort()).toEqual([...b.keys()].sort());
  for (const [k, v] of a) {
    expect(b.get(k)?.equals(v), `byte mismatch: ${k}`).toBe(true);
  }
}

describe("mergeVarMaps: no silent newer-wins", () => {
  it("both-changed with base → conflict", () => {
    const base = vault({ a: { createdAt: 1, vars: { K: entry("base", 1) } } });
    const ours = vault({ a: { createdAt: 1, vars: { K: entry("ours", 10) } } });
    const theirs = vault({ a: { createdAt: 1, vars: { K: entry("theirs", 20) } } });
    const { conflicts, merged } = threeWayMerge(ours, theirs, base, new Map(), "USB");
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0].key).toBe("K");
    expect(merged.projects.a.vars.K).toBeUndefined();
  });

  it("both-changed without base → conflict", () => {
    const ours = vault({ a: { createdAt: 1, vars: { K: entry("ours", 10) } } });
    const theirs = vault({ a: { createdAt: 1, vars: { K: entry("theirs", 20) } } });
    const { conflicts } = threeWayMerge(ours, theirs, null, new Map(), "USB");
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0].key).toBe("K");
  });

  it("only-theirs-changed → auto-take theirs", () => {
    const base = vault({ a: { createdAt: 1, vars: { K: entry("base", 1) } } });
    const ours = vault({ a: { createdAt: 1, vars: { K: entry("base", 1) } } });
    const theirs = vault({ a: { createdAt: 1, vars: { K: entry("theirs", 5) } } });
    const { conflicts, merged } = threeWayMerge(ours, theirs, base, new Map(), "USB");
    expect(conflicts).toHaveLength(0);
    expect(merged.projects.a.vars.K.value).toBe("theirs");
  });

  it("only-ours-changed → keep ours", () => {
    const base = vault({ a: { createdAt: 1, vars: { K: entry("base", 1) } } });
    const ours = vault({ a: { createdAt: 1, vars: { K: entry("ours", 5) } } });
    const theirs = vault({ a: { createdAt: 1, vars: { K: entry("base", 1) } } });
    const { conflicts, merged } = threeWayMerge(ours, theirs, base, new Map(), "USB");
    expect(conflicts).toHaveLength(0);
    expect(merged.projects.a.vars.K.value).toBe("ours");
  });
});

describe("project deletions + allow-deletes", () => {
  it("matching base with real deletion → reports projectDeletions", () => {
    const base = vault({
      keep: { createdAt: 1, vars: { A: entry("1") } },
      gone: { createdAt: 1, vars: { B: entry("2") } },
    });
    const ours = vault({
      keep: { createdAt: 1, vars: { A: entry("1") } },
      gone: { createdAt: 1, vars: { B: entry("2") } },
    });
    const theirs = vault({
      keep: { createdAt: 1, vars: { A: entry("1") } },
    });
    const { projectDeletions, merged } = threeWayMerge(ours, theirs, base, new Map(), "USB");
    expect(projectDeletions).toEqual([{ project: "gone", side: "peer" }]);
    expect(merged.projects.gone).toBeUndefined();
    const lines = formatProjectDeletionLines(projectDeletions, "USB");
    expect(lines.some((l) => l.includes("DELETE project gone"))).toBe(true);
  });

  it("stale/mismatched base (null) → no deletions; missing peer projects kept", () => {
    const ours = vault({
      localOnly: { createdAt: 1, vars: { A: entry("1") } },
      shared: { createdAt: 1, vars: { B: entry("2") } },
    });
    const theirs = vault({
      shared: { createdAt: 1, vars: { B: entry("2") } },
    });
    const { projectDeletions, merged } = threeWayMerge(ours, theirs, null, new Map(), "USB");
    expect(projectDeletions).toHaveLength(0);
    expect(merged.projects.localOnly).toBeDefined();
    expect(merged.projects.shared).toBeDefined();
  });
});

describe.runIf(!skipWin)("per-peer sync-state", () => {
  const envBackup = { ...process.env };
  let tmp = "";

  afterEach(() => {
    if (tmp) cleanupTemp(tmp, envBackup);
    tmp = "";
  });

  it("per-peer entries do not clobber each other; legacy v1 never used as base", async () => {
    const v = vault({ a: { createdAt: 1, vars: { K: entry("v") } } });
    ({ tmp } = await setupTempVault(v));

    await saveSyncState("usb:lineage-a", v);
    const v2 = vault({ a: { createdAt: 1, vars: { K: entry("v2") } } });
    await saveSyncState("lan:device-b", v2);

    const a = await loadSyncState("usb:lineage-a");
    const b = await loadSyncState("lan:device-b");
    expect(a?.base.projects.a.vars.K.value).toBe("v");
    expect(b?.base.projects.a.vars.K.value).toBe("v2");
    expect(await loadSyncState("usb:other")).toBeNull();

    // Legacy v1 encrypted file → never used as base
    const key = await platform.getMasterKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const plain = Buffer.from(JSON.stringify({ lastSyncAt: 1, base: v }), "utf8");
    const data = Buffer.concat([cipher.update(plain), cipher.final()]);
    fs.writeFileSync(
      syncStateFile(),
      JSON.stringify({
        format: "abracadabra-sync-state",
        version: 1,
        iv: iv.toString("base64"),
        tag: cipher.getAuthTag().toString("base64"),
        data: data.toString("base64"),
      }),
      { mode: 0o600 },
    );
    expect(await loadSyncState("usb:lineage-a")).toBeNull();

    // Next save replaces with v2
    await saveSyncState("usb:fresh", v);
    expect(await loadSyncState("usb:fresh")).not.toBeNull();
    expect(await loadSyncState("usb:lineage-a")).toBeNull();
  });

  it("device-id is created lazily (0600) and peer helpers work", async () => {
    ({ tmp } = await setupTempVault(vault({})));
    const id = getOrCreateDeviceId();
    expect(id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
    expect(getOrCreateDeviceId()).toBe(id);
    const st = fs.statSync(path.join(abraDir(), "device-id"));
    expect(st.mode & 0o777).toBe(0o600);
    expect(usbPeerId("abc")).toBe("usb:abc");
    expect(usbPeerId(undefined)).toBeNull();
    expect(lanPeerId(id)).toBe(`lan:${id}`);
    expect(lanPeerId(undefined)).toBeNull();
  });
});

describe.runIf(!skipWin)("approval before write + passphrase min", () => {
  const envBackup = { ...process.env };
  let tmp = "";

  beforeEach(() => {
    vi.mocked(platform.authenticate).mockClear();
    vi.mocked(platform.authenticate).mockImplementation(async () => {});
  });

  afterEach(() => {
    if (tmp) cleanupTemp(tmp, envBackup);
    tmp = "";
  });

  it("assertUsbPassphrase rejects 11, accepts 12", () => {
    expect(USB_PASSPHRASE_MIN).toBe(12);
    expect(() => assertUsbPassphrase("12345678901")).toThrow(/12 characters/);
    expect(() => assertUsbPassphrase("123456789012")).not.toThrow();
  });

  it("createBackup rejects 11-char passphrase (nothing written)", async () => {
    ({ tmp } = await setupTempVault(vault({ p: { createdAt: 1, vars: { A: entry("1") } } })));
    const stick = path.join(tmp, "stick");
    fs.mkdirSync(stick);
    const before = snapshotBytes(tmp);
    const { createBackup } = await import("../commands/usb.js");
    await expect(createBackup(stick, "12345678901")).rejects.toThrow(/12 characters/);
    expectMapsEqual(before, snapshotBytes(tmp));
  });

  it("createBackup accepts 12-char passphrase", async () => {
    ({ tmp } = await setupTempVault(vault({ p: { createdAt: 1, vars: { A: entry("1") } } })));
    const stick = path.join(tmp, "stick");
    fs.mkdirSync(stick);
    const { createBackup } = await import("../commands/usb.js");
    const file = await createBackup(stick, "123456789012");
    expect(fs.existsSync(file)).toBe(true);
    const opened = openBundle(readBundleFile(file), "123456789012");
    expect(opened.meta.lineageId).toBeTruthy();
    expect(opened.meta.deviceId).toBeTruthy();
  });

  it("createScopedBackup rejects 11-char passphrase", async () => {
    ({ tmp } = await setupTempVault(vault({ p: { createdAt: 1, vars: { A: entry("1") } } })));
    const stick = path.join(tmp, "stick");
    fs.mkdirSync(stick);
    const before = snapshotBytes(tmp);
    const { createScopedBackup } = await import("../commands/usb.js");
    await expect(createScopedBackup(stick, ["p"], "12345678901")).rejects.toThrow(/12 characters/);
    expectMapsEqual(before, snapshotBytes(tmp));
  });

  it("denied authenticate leaves vault/sync-state/bundle byte-identical (applySync)", async () => {
    const local = vault({ p: { createdAt: 1, vars: { A: entry("local", 2) } } });
    const { masterKey } = await setupTempVault(local);
    tmp = process.env.ABRA_DIR!;
    const stick = path.join(tmp, "stick");
    const bundleDir = path.join(stick, "abracadabra");
    fs.mkdirSync(bundleDir, { recursive: true });
    const remote = vault({ p: { createdAt: 1, vars: { A: entry("remote", 3) } } });
    const lineageId = crypto.randomUUID();
    const bundle = sealBundle(encryptVault(remote, masterKey), masterKey, "twelvechars!!", {
      lineageId,
    });
    const file = path.join(bundleDir, "backup-test.abrabak");
    fs.writeFileSync(file, JSON.stringify(bundle), { mode: 0o600 });
    fs.writeFileSync(
      path.join(bundleDir, "latest.json"),
      JSON.stringify({ file: "backup-test.abrabak", createdAt: 1 }),
    );
    await saveSyncState(usbPeerId(lineageId), local);

    const before = snapshotBytes(tmp);
    vi.mocked(platform.authenticate).mockRejectedValueOnce(new Error("denied"));
    const { applySync } = await import("../commands/usb.js");
    await expect(applySync(stick, "twelvechars!!", "ours")).rejects.toThrow(/denied/);
    expectMapsEqual(before, snapshotBytes(tmp));
  });

  it("matching base deletion requires --allow-deletes; applies with it", async () => {
    const base = vault({
      keep: { createdAt: 1, vars: { A: entry("1") } },
      gone: { createdAt: 1, vars: { B: entry("2") } },
    });
    const local = { ...base };
    const { masterKey } = await setupTempVault(local);
    tmp = process.env.ABRA_DIR!;
    const stick = path.join(tmp, "stick");
    const bundleDir = path.join(stick, "abracadabra");
    fs.mkdirSync(bundleDir, { recursive: true });
    const remote = vault({ keep: { createdAt: 1, vars: { A: entry("1") } } });
    const lineageId = crypto.randomUUID();
    const bundle = sealBundle(encryptVault(remote, masterKey), masterKey, "twelvechars!!", {
      lineageId,
    });
    fs.writeFileSync(path.join(bundleDir, "backup-test.abrabak"), JSON.stringify(bundle), {
      mode: 0o600,
    });
    fs.writeFileSync(
      path.join(bundleDir, "latest.json"),
      JSON.stringify({ file: "backup-test.abrabak", createdAt: 1 }),
    );
    await saveSyncState(usbPeerId(lineageId), base);

    const { applySync, UsbProjectDeleteError, previewSync } = await import("../commands/usb.js");
    const preview = await previewSync(stick, "twelvechars!!");
    expect(preview.projectDeletions.some((d) => d.project === "gone")).toBe(true);
    expect(preview.report.some((l) => /DELETE project gone/.test(l))).toBe(true);

    await expect(applySync(stick, "twelvechars!!")).rejects.toBeInstanceOf(UsbProjectDeleteError);
    expect((await loadVault()).projects.gone).toBeDefined();

    const result = await applySync(stick, "twelvechars!!", undefined, true);
    expect(result.changed).toBe(true);
    expect((await loadVault()).projects.gone).toBeUndefined();
  });

  it("legacy short passphrase still opens with warning", async () => {
    const local = vault({ p: { createdAt: 1, vars: { A: entry("1") } } });
    const { masterKey } = await setupTempVault(local);
    tmp = process.env.ABRA_DIR!;
    // Bypass assertUsbPassphrase by sealing directly with 8-char pass
    const short = "short8ch";
    const bundle = sealBundle(encryptVault(local, masterKey), masterKey, short, {
      lineageId: crypto.randomUUID(),
    });
    const opened = openBundle(bundle, short);
    expect(opened.meta.hostname).toBeTruthy();
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { warnIfShortBundlePassphrase } = await import("./passphrase.js");
    warnIfShortBundlePassphrase(short);
    expect(errSpy).toHaveBeenCalledWith(
      expect.stringMatching(/shorter than 12 characters/),
    );
    errSpy.mockRestore();
  });

  it("stale peer base does not delete local-only projects", async () => {
    const peerABase = vault({
      shared: { createdAt: 1, vars: { A: entry("1") } },
      onlyA: { createdAt: 1, vars: { X: entry("x") } },
    });
    const local = vault({
      shared: { createdAt: 1, vars: { A: entry("1") } },
      onlyA: { createdAt: 1, vars: { X: entry("x") } },
      localExtra: { createdAt: 1, vars: { L: entry("l") } },
    });
    const { masterKey } = await setupTempVault(local);
    tmp = process.env.ABRA_DIR!;
    // Base recorded for peer A
    await saveSyncState("usb:peer-a", peerABase);

    // Syncing with peer B (different lineage) — no base → additive
    const stick = path.join(tmp, "stick");
    const bundleDir = path.join(stick, "abracadabra");
    fs.mkdirSync(bundleDir, { recursive: true });
    const remote = vault({ shared: { createdAt: 1, vars: { A: entry("1") } } });
    const lineageB = "peer-b-lineage";
    const bundle = sealBundle(encryptVault(remote, masterKey), masterKey, "twelvechars!!", {
      lineageId: lineageB,
    });
    fs.writeFileSync(path.join(bundleDir, "backup-test.abrabak"), JSON.stringify(bundle), {
      mode: 0o600,
    });
    fs.writeFileSync(
      path.join(bundleDir, "latest.json"),
      JSON.stringify({ file: "backup-test.abrabak", createdAt: 1 }),
    );

    const { applySync } = await import("../commands/usb.js");
    const result = await applySync(stick, "twelvechars!!");
    expect(result.changed).toBe(true);
    const after = await loadVault();
    expect(after.projects.onlyA).toBeDefined();
    expect(after.projects.localExtra).toBeDefined();
    expect(after.projects.shared).toBeDefined();
    // peer A entry untouched
    expect((await loadSyncState("usb:peer-a"))?.base.projects.onlyA).toBeDefined();
  });
});

describe.runIf(!skipWin)("applyLanSync denied approval writes nothing", () => {
  const envBackup = { ...process.env };
  let tmp = "";
  let hostHandle: { stop: () => Promise<void>; pin: string; fingerprint: string; port: number } | null =
    null;

  beforeEach(() => {
    vi.mocked(platform.authenticate).mockClear();
    vi.mocked(platform.authenticate).mockImplementation(async () => {});
  });

  afterEach(async () => {
    if (hostHandle) {
      try {
        await hostHandle.stop();
      } catch {
        /* ignore */
      }
      hostHandle = null;
    }
    const { stopLanHost } = await import("../usb/lan-host.js");
    try {
      await stopLanHost();
    } catch {
      /* ignore */
    }
    if (tmp) cleanupTemp(tmp, envBackup);
    tmp = "";
  }, 15_000);

  it("denied authenticate leaves vault + sync-state identical", async () => {
    const local = vault({
      here: { createdAt: 1, vars: { A: entry("1") } },
      both: { createdAt: 1, vars: { B: entry("2") } },
    });
    ({ tmp } = await setupTempVault(local));

    const { startLanHost } = await import("../usb/lan-host.js");
    hostHandle = await startLanHost({ port: 0, advertise: false, ttlMs: 60_000 });

    // Host vault is the same machine in this test setup — pull will match.
    // Force a change by saving a different remote-looking state is hard on same vault.
    // Instead: deny on already-in-sync path (still authenticates before sync-state write).
    const before = {
      vault: fs.readFileSync(vaultFile()),
      sync: fs.existsSync(syncStateFile()) ? fs.readFileSync(syncStateFile()) : null,
    };
    vi.mocked(platform.authenticate).mockRejectedValueOnce(new Error("denied"));
    const { applyLanSync } = await import("../usb/lan-client.js");
    await expect(
      applyLanSync(
        `127.0.0.1:${hostHandle.port}`,
        hostHandle.pin,
        undefined,
        hostHandle.fingerprint,
      ),
    ).rejects.toThrow(/denied/);
    expect(fs.readFileSync(vaultFile()).equals(before.vault)).toBe(true);
    const afterSync = fs.existsSync(syncStateFile()) ? fs.readFileSync(syncStateFile()) : null;
    if (before.sync === null) expect(afterSync).toBeNull();
    else expect(afterSync!.equals(before.sync)).toBe(true);
  });
});

describe.runIf(!skipWin)("LAN host delete gate", () => {
  const envBackup = { ...process.env };
  let tmp = "";

  afterEach(async () => {
    const { stopLanHost } = await import("../usb/lan-host.js");
    await stopLanHost();
    if (tmp) cleanupTemp(tmp, envBackup);
    tmp = "";
  });

  async function pushRaw(port: number, pin: string, bundle: unknown): Promise<{ status: number; json: any }> {
    const https = await import("node:https");
    const body = JSON.stringify({ bundle });
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: "127.0.0.1",
          port,
          path: "/lan/push",
          method: "POST",
          rejectUnauthorized: false,
          headers: {
            Authorization: `Bearer ${pin}`,
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(body),
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
      req.write(body);
      req.end();
    });
  }

  for (const allowDeletes of [false, true]) {
    it(`push that drops a host project is ${allowDeletes ? "applied with" : "refused without"} --allow-deletes`, async () => {
      ({ tmp } = await setupTempVault(
        vault({ keep: { createdAt: 1, vars: { A: entry("a") } }, treasuryish: { createdAt: 1, vars: { W: entry("w") } } }),
      ));
      const before = fs.readFileSync(vaultFile());
      const { startLanHost, getLanHostStatus } = await import("../usb/lan-host.js");
      await startLanHost({ advertise: false, port: 0, ttlMs: 60_000, allowDeletes });
      const status = getLanHostStatus()!;
      vi.mocked(platform.authenticate).mockClear();

      const peerKey = crypto.randomBytes(32);
      const pushed = vault({ keep: { createdAt: 1, vars: { A: entry("a") } } });
      const bundle = sealBundle(encryptVault(pushed, peerKey), peerKey, status.pin);
      const res = await pushRaw(status.port, status.pin, bundle);

      if (!allowDeletes) {
        expect(res.status).toBe(409);
        expect(res.json.projectDeletions).toEqual(["treasuryish"]);
        expect(vi.mocked(platform.authenticate)).not.toHaveBeenCalled();
        expect(Buffer.compare(before, fs.readFileSync(vaultFile()))).toBe(0);
      } else {
        expect(res.status).toBe(200);
        expect(vi.mocked(platform.authenticate)).toHaveBeenCalledTimes(1);
        expect(Object.keys((await loadVault()).projects)).toEqual(["keep"]);
      }
    }, 20_000);
  }
});
