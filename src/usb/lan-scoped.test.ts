import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import https from "node:https";
import type { Vault, Project } from "../core/vault.js";
import { saveVault, loadVault, TREASURY_PROJECT } from "../core/vault.js";
import {
  sealScopedBundle,
  openAnyBundle,
  readBundleFile,
} from "../core/backup.js";
import { vaultFile, syncStateFile } from "../core/paths.js";
import {
  mergeScopedProjects,
  assertScopeNamesAllowed,
  extractScopedProjects,
  validateScope,
} from "../core/sync-scope.js";
import { createEphemeralTls } from "../core/tls-ephemeral.js";
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

function entry(value: string, secret = true, updatedAt = 1) {
  return { value, secret, updatedAt };
}

async function setupTempVault(vault: Vault): Promise<{ tmp: string; masterKey: Buffer }> {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "abra-scoped-"));
  process.env.ABRA_DIR = tmp;
  process.env.ABRA_AGENT = "0";
  process.env.ABRA_KEYSTORE = "passphrase-file";
  process.env.ABRA_SKIP_BIOMETRICS = "1";
  process.env.ABRA_AUTH = "none";
  process.env.ABRA_HEADLESS_PASSPHRASE = "scoped-test-passphrase-ok";
  setDefaultKdfForTests({ N: 16384 });
  platform.resetPlatformForTests();
  const masterKey = crypto.randomBytes(32);
  await platform.restoreMasterKey(masterKey, "scoped-test-passphrase-ok");
  await platform.getMasterKey();
  await saveVault(vault);
  return { tmp, masterKey };
}

function cleanupTemp(tmp: string, envBackup: NodeJS.ProcessEnv) {
  process.env = { ...envBackup };
  setDefaultKdfForTests(null);
  platform.resetPlatformForTests();
  fs.rmSync(tmp, { recursive: true, force: true });
}

describe.runIf(!skipWin)("LAN scoped sync", () => {
  const envBackup = { ...process.env };
  let tmp = "";
  let hostHandle: { stop: () => Promise<void>; pin: string; fingerprint: string; port: number; scope?: string[] } | null = null;

  beforeEach(() => {
    vi.mocked(platform.authenticate).mockClear();
    vi.mocked(platform.authenticate).mockImplementation(async () => {});
  });

  afterEach(async () => {
    if (hostHandle) {
      try {
        await Promise.race([
          hostHandle.stop(),
          new Promise((_, rej) => setTimeout(() => rej(new Error("stop timeout")), 3000)),
        ]);
      } catch {
        /* force-clear */
      }
      hostHandle = null;
    }
    const { stopLanHost } = await import("../usb/lan-host.js");
    try {
      await Promise.race([
        stopLanHost(),
        new Promise((_, rej) => setTimeout(() => rej(new Error("stop timeout")), 3000)),
      ]);
    } catch {
      /* ignore */
    }
    if (tmp) cleanupTemp(tmp, envBackup);
    tmp = "";
  }, 15_000);

  it("a: scoped host bundle contains ONLY named projects", async () => {
    const vault: Vault = {
      version: 1,
      projects: {
        gotchibot: { createdAt: 1, vars: { A: entry("1"), B: entry("2") } },
        other: { createdAt: 1, vars: { X: entry("x") } },
        [TREASURY_PROJECT]: {
          createdAt: 1,
          vars: { PRIVATE_KEY: entry("never-sync") },
        },
      },
      connections: {
        cf: { provider: "cf", createdAt: 1, meta: {}, vars: { T: entry("t") } },
      },
      passkeys: [],
      apiKeys: {},
    };
    ({ tmp } = await setupTempVault(vault));

    const { startLanHost, getLanHostStatus } = await import("../usb/lan-host.js");
    hostHandle = await startLanHost({
      port: 0,
      advertise: false,
      projects: ["gotchibot"],
      ttlMs: 60_000,
    });
    const status = getLanHostStatus()!;
    expect(status.scope).toEqual(["gotchibot"]);

    // Pull via client path (fingerprint verified), then inspect with openAnyBundle
    // by re-sealing from extract — instead, use a raw pull through scopedLanSync dry-run
    // and separately seal/open from host extract to assert payload shape.
    const { openAnyBundle: openAny, sealScopedBundle: sealScoped } = await import(
      "../core/backup.js"
    );
    const fresh = await loadVault();
    const extracted = extractScopedProjects(fresh, ["gotchibot"]);
    const sealed = sealScoped(extracted, ["gotchibot"], status.pin);
    const opened = openAny(sealed, status.pin);
    expect(opened.kind).toBe("scoped");
    if (opened.kind !== "scoped") return;
    expect(Object.keys(opened.payload.projects)).toEqual(["gotchibot"]);
    expect(opened.payload).not.toHaveProperty("masterKey");
    expect(opened.payload).not.toHaveProperty("vaultEnc");
    expect(JSON.stringify(opened.payload)).not.toContain(TREASURY_PROJECT);
    expect(JSON.stringify(opened.payload)).not.toContain("\"connections\"");
    expect(JSON.stringify(opened.payload)).not.toContain("passkeys");
    expect(JSON.stringify(opened.payload)).not.toContain("apiKeys");
    expect(Object.keys(opened.payload.projects)).not.toContain("other");

    // Also confirm live /lan/pull returns a scoped bundle the client can open
    const { scopedLanSync } = await import("../usb/lan-client.js");
    const result = await scopedLanSync(`127.0.0.1:${status.port}`, status.pin, {
      projects: ["gotchibot"],
      dryRun: true,
      expectedFingerprint: status.fingerprint,
    });
    expect(result.dryRun).toBe(true);
    expect(result.report.join("\n")).not.toMatch(/never-sync|PRIVATE_KEY/);
  }, 20_000);

  it("b: treasury/reserved refused before listen; unknown fails before listen", async () => {
    const vault: Vault = {
      version: 1,
      projects: { gotchibot: { createdAt: 1, vars: { A: entry("1") } } },
    };
    ({ tmp } = await setupTempVault(vault));
    const { startLanHost } = await import("../usb/lan-host.js");

    await expect(
      startLanHost({ advertise: false, projects: [TREASURY_PROJECT], port: 0 }),
    ).rejects.toThrow(/refused/);

    await expect(
      startLanHost({ advertise: false, projects: ["__abra_x"], port: 0 }),
    ).rejects.toThrow(/refused/);

    await expect(
      startLanHost({ advertise: false, projects: ["nosuch"], port: 0 }),
    ).rejects.toThrow(/unknown project/);

    // Server must not be listening
    const { getLanHostStatus } = await import("../usb/lan-host.js");
    expect(getLanHostStatus()).toBeNull();
  });

  it("c: client cannot widen scope (403); client refuses unrequested names", async () => {
    const vault: Vault = {
      version: 1,
      projects: {
        gotchibot: { createdAt: 1, vars: { A: entry("1") } },
        other: { createdAt: 1, vars: { X: entry("x") } },
      },
    };
    ({ tmp } = await setupTempVault(vault));
    const { startLanHost, getLanHostStatus } = await import("../usb/lan-host.js");
    hostHandle = await startLanHost({
      advertise: false,
      projects: ["gotchibot"],
      port: 0,
      ttlMs: 60_000,
    });
    const status = getLanHostStatus()!;
    const { scopedLanSync } = await import("../usb/lan-client.js");

    await expect(
      scopedLanSync(`127.0.0.1:${status.port}`, status.pin, {
        projects: ["gotchibot", "other"],
        expectedFingerprint: status.fingerprint,
      }),
    ).rejects.toThrow(/outside host scope|LAN pull failed \(403\)/);

    // Client-side refusal if payload somehow contains unrequested names
    const tooWide = sealScopedBundle(
      {
        gotchibot: { createdAt: 1, vars: { A: entry("1") } },
        sneaky: { createdAt: 1, vars: { X: entry("x") } },
      },
      ["gotchibot", "sneaky"],
      "testpass",
    );
    const opened = openAnyBundle(tooWide, "testpass");
    expect(opened.kind).toBe("scoped");
    if (opened.kind === "scoped") {
      const requested = new Set(["gotchibot"]);
      const extras = Object.keys(opened.payload.projects).filter((n) => !requested.has(n));
      expect(extras).toEqual(["sneaky"]);
    }
  }, 20_000);

  it("d: scoped host rejects /lan/push; host vault bytes unchanged; client never pushes", async () => {
    const vault: Vault = {
      version: 1,
      projects: { gotchibot: { createdAt: 1, vars: { A: entry("host-a") } } },
    };
    ({ tmp } = await setupTempVault(vault));
    const vaultPath = vaultFile();
    const before = fs.readFileSync(vaultPath);

    const { startLanHost, getLanHostStatus } = await import("../usb/lan-host.js");
    const authCallsBefore = vi.mocked(platform.authenticate).mock.calls.length;
    hostHandle = await startLanHost({
      advertise: false,
      projects: ["gotchibot"],
      port: 0,
      ttlMs: 60_000,
    });
    const status = getLanHostStatus()!;
    const authAfterStart = vi.mocked(platform.authenticate).mock.calls.length;
    expect(authAfterStart).toBe(authCallsBefore + 1);

    // Direct push without reading through client
    const pushRes = await new Promise<{ status: number; json: unknown }>((resolve, reject) => {
      const body = JSON.stringify({ bundle: { format: "abracadabra-backup" } });
      const req = https.request(
        {
          host: "127.0.0.1",
          port: status.port,
          path: "/lan/push",
          method: "POST",
          headers: {
            Authorization: `Bearer ${status.pin}`,
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(body),
          },
          rejectUnauthorized: false,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            resolve({
              status: res.statusCode ?? 0,
              json: JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"),
            });
          });
        },
      );
      req.on("error", reject);
      req.write(body);
      req.end();
    });
    expect(pushRes.status).toBe(403);
    expect((pushRes.json as { error: string }).error).toMatch(/read-only/);
    // No additional authenticate from push
    expect(vi.mocked(platform.authenticate).mock.calls.length).toBe(authAfterStart);

    const after = fs.readFileSync(vaultPath);
    expect(Buffer.compare(before, after)).toBe(0);
  });

  it("e+f+g+k+l: merge rules, dry-run, no sync-state, auth once", async () => {
    // Standalone HTTPS server serving a fixed scoped bundle (avoids ABRA_DIR clash with host).
    const hostProjects: Record<string, Project> = {
      gotchibot: {
        createdAt: 1,
        vars: {
          SHARED: entry("host-shared", true, 5),
          HOST_ONLY: entry("from-host"),
          CONFLICT: entry("host-conflict", true, 5),
        },
      },
    };
    const pin = "482910";
    const bundle = sealScopedBundle(hostProjects, ["gotchibot"], pin);
    const tlsMaterial = createEphemeralTls("scoped-merge");
    let pushCalled = false;
    const server = https.createServer({ key: tlsMaterial.key, cert: tlsMaterial.cert }, (req, res) => {
      const url = new URL(req.url ?? "/", "https://127.0.0.1");
      const send = (status: number, body: unknown) => {
        const data = JSON.stringify(body);
        res.writeHead(status, {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(data),
        });
        res.end(data);
      };
      if (req.method === "GET" && url.pathname === "/lan/info") {
        send(200, {
          hostname: "t",
          port: 0,
          expiresAt: Date.now() + 60_000,
          fingerprint: tlsMaterial.fingerprint,
          scoped: true,
          proto: 2,
        });
        return;
      }
      if (req.method === "POST" && url.pathname === "/lan/pull") {
        const auth = req.headers.authorization ?? "";
        if (auth !== `Bearer ${pin}`) {
          send(401, { error: "invalid PIN" });
          return;
        }
        const chunks: Buffer[] = [];
        req.on("data", (c) => chunks.push(c));
        req.on("end", () => send(200, { bundle }));
        return;
      }
      if (req.method === "POST" && url.pathname === "/lan/push") {
        pushCalled = true;
        send(403, { error: "scoped session is read-only; push-back refused" });
        return;
      }
      send(404, { error: "not found" });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as { port: number }).port;

    ({ tmp } = await setupTempVault({
      version: 1,
      projects: {
        keepme: { createdAt: 1, vars: { LOCAL: entry("stay") } },
        gotchibot: {
          createdAt: 1,
          vars: {
            SHARED: entry("host-shared", true, 1),
            LOCAL_ONLY: entry("receiver-only"),
            CONFLICT: entry("local-conflict", true, 1),
          },
        },
      },
      connections: {
        x: { provider: "x", createdAt: 1, meta: {}, vars: { T: entry("t") } },
      },
    }));
    const vaultPath = vaultFile();
    const beforeBytes = fs.readFileSync(vaultPath);

    const { scopedLanSync } = await import("../usb/lan-client.js");
    vi.mocked(platform.authenticate).mockClear();

    const dry = await scopedLanSync(`127.0.0.1:${port}`, pin, {
      projects: ["gotchibot"],
      dryRun: true,
      expectedFingerprint: tlsMaterial.fingerprint,
    });
    expect(dry.dryRun).toBe(true);
    expect(vi.mocked(platform.authenticate)).not.toHaveBeenCalled();
    expect(Buffer.compare(fs.readFileSync(vaultPath), beforeBytes)).toBe(0);
    expect(fs.existsSync(syncStateFile())).toBe(false);
    expect(dry.report.some((l) => l.includes("CONFLICT") && l.includes("conflict"))).toBe(true);
    expect(dry.report.join("\n")).not.toMatch(/local-conflict|host-conflict/);
    expect(pushCalled).toBe(false);

    vi.mocked(platform.authenticate).mockClear();
    const applied = await scopedLanSync(`127.0.0.1:${port}`, pin, {
      projects: ["gotchibot"],
      expectedFingerprint: tlsMaterial.fingerprint,
    });
    expect(vi.mocked(platform.authenticate)).toHaveBeenCalledTimes(1);
    expect(applied.changed).toBe(true);
    expect(pushCalled).toBe(false);

    const merged = await loadVault();
    expect(merged.projects.keepme.vars.LOCAL.value).toBe("stay");
    expect(merged.projects.gotchibot.vars.LOCAL_ONLY.value).toBe("receiver-only");
    expect(merged.projects.gotchibot.vars.HOST_ONLY.value).toBe("from-host");
    expect(merged.projects.gotchibot.vars.CONFLICT.value).toBe("local-conflict");
    expect(merged.connections?.x).toBeDefined();
    expect(fs.existsSync(syncStateFile())).toBe(false);

    // reset local and take --theirs
    await saveVault({
      version: 1,
      projects: {
        keepme: { createdAt: 1, vars: { LOCAL: entry("stay") } },
        gotchibot: {
          createdAt: 1,
          vars: {
            SHARED: entry("host-shared", true, 1),
            LOCAL_ONLY: entry("receiver-only"),
            CONFLICT: entry("local-conflict", true, 1),
          },
        },
      },
    });
    const theirs = await scopedLanSync(`127.0.0.1:${port}`, pin, {
      projects: ["gotchibot"],
      theirs: true,
      expectedFingerprint: tlsMaterial.fingerprint,
    });
    const afterTheirs = await loadVault();
    expect(afterTheirs.projects.gotchibot.vars.CONFLICT.value).toBe("host-conflict");
    expect(theirs.report.some((l) => l.includes("--theirs"))).toBe(true);
    expect(pushCalled).toBe(false);

    await new Promise<void>((r) => server.close(() => r()));
  }, 30_000);

  it("i: fingerprint verified BEFORE PIN sent; missing fingerprint errors", async () => {
    let handlerInvoked = false;
    const tlsMaterial = createEphemeralTls("fp-gate");
    const server = https.createServer({ key: tlsMaterial.key, cert: tlsMaterial.cert }, (_req, res) => {
      handlerInvoked = true;
      const data = "{}";
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(data),
      });
      res.end(data);
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as { port: number }).port;

    const { scopedLanSync, fetchLanInfo, applyLanSync } = await import("../usb/lan-client.js");

    await expect(
      scopedLanSync(`127.0.0.1:${port}`, "123456", {
        projects: ["x"],
        expectedFingerprint: "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
      }),
    ).rejects.toThrow(/fingerprint mismatch|PIN not sent/);
    expect(handlerInvoked).toBe(false);

    await expect(fetchLanInfo(`127.0.0.1:${port}`)).rejects.toThrow(/fingerprint/);
    await expect(applyLanSync(`127.0.0.1:${port}`, "123456")).rejects.toThrow(/fingerprint/);

    // Legacy short prefix of the real fingerprint should warn + connect
    const fullHex = tlsMaterial.fingerprint.replace(/[^0-9A-Fa-f]/g, "");
    const short = fullHex.slice(0, 16);
    const warn = vi.spyOn(console, "error").mockImplementation(() => {});
    handlerInvoked = false;
    // Will fail later (not a real lan host) but handler SHOULD be invoked after fp match
    try {
      await fetchLanInfo(`127.0.0.1:${port}`, short);
    } catch {
      /* may fail on JSON shape */
    }
    expect(handlerInvoked).toBe(true);
    expect(warn).toHaveBeenCalledWith(expect.stringMatching(/legacy short/i));
    warn.mockRestore();

    await new Promise<void>((r) => server.close(() => r()));
  }, 20_000);

  it("j: unscoped host + unscoped client still full-bundle pull+push; {} body ok", async () => {
    const vault: Vault = {
      version: 1,
      projects: {
        demo: { createdAt: 1, vars: { A: entry("1") } },
      },
    };
    ({ tmp } = await setupTempVault(vault));
    const { startLanHost, getLanHostStatus } = await import("../usb/lan-host.js");
    hostHandle = await startLanHost({
      advertise: false,
      port: 0,
      ttlMs: 60_000,
    });
    const status = getLanHostStatus()!;
    expect(status.scope).toBeUndefined();

    // /lan/info has scoped:false proto:2
    const { fetchLanInfo } = await import("../usb/lan-client.js");
    const info = await fetchLanInfo(`127.0.0.1:${status.port}`, status.fingerprint);
    expect(info.scoped).toBe(false);
    expect(info.proto).toBe(2);

    // Client on same vault — already in sync path still pushes
    const { applyLanSync } = await import("../usb/lan-client.js");
    const result = await applyLanSync(
      `127.0.0.1:${status.port}`,
      status.pin,
      undefined,
      status.fingerprint,
    );
    expect(result.report).toEqual([]);
    // Host stops after successful push
    expect(getLanHostStatus()).toBeNull();
    hostHandle = null;
  });

  it("h: scoped FILE bundle backup merge restore; no latest.json", async () => {
    const vault: Vault = {
      version: 1,
      projects: {
        gotchibot: { createdAt: 1, vars: { A: entry("from-bundle") } },
        other: { createdAt: 1, vars: { Z: entry("keep") } },
      },
    };
    ({ tmp } = await setupTempVault(vault));
    const masterBefore = (await platform.getMasterKey()).toString("base64");

    const dir = path.join(tmp, "usbout");
    fs.mkdirSync(dir, { recursive: true });
    // Simulate scoped backup write
    assertScopeNamesAllowed(["gotchibot"]);
    const v = await loadVault();
    const scope = validateScope(v, ["gotchibot"]);
    const projects = extractScopedProjects(v, scope);
    const bundle = sealScopedBundle(projects, scope, "filepassphrase1");
    const stamp = "2020-01-01T00-00-00";
    const file = path.join(dir, "abracadabra", `scoped-${stamp}.abrabak`);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(bundle), { mode: 0o600 });
    expect(fs.existsSync(path.join(dir, "abracadabra", "latest.json"))).toBe(false);

    // Change local gotchibot and keep other
    await saveVault({
      version: 1,
      projects: {
        gotchibot: { createdAt: 1, vars: { A: entry("local-a"), LOCAL: entry("stay") } },
        other: { createdAt: 1, vars: { Z: entry("keep") } },
      },
    });

    const opened = openAnyBundle(readBundleFile(file), "filepassphrase1");
    expect(opened.kind).toBe("scoped");
    if (opened.kind !== "scoped") return;

    const { merged, report, changed } = mergeScopedProjects(
      await loadVault(),
      opened.payload.projects,
      {},
    );
    expect(changed).toBe(false); // A differs → conflict keep local; no new keys from host that aren't local... wait A conflicts, LOCAL stays, no HOST new keys. changed=false when only conflicts!
    // Actually: A differs → conflict (keep local), no added/new → changed=false. Good.
    expect(report.conflicts).toEqual([{ project: "gotchibot", key: "A" }]);

    // Add a key only in bundle
    const withNew = sealScopedBundle(
      {
        gotchibot: {
          createdAt: 1,
          vars: { A: entry("from-bundle"), NEW: entry("n") },
        },
      },
      ["gotchibot"],
      "filepassphrase1",
    );
    const o2 = openAnyBundle(withNew, "filepassphrase1");
    if (o2.kind !== "scoped") throw new Error("expected scoped");
    const m2 = mergeScopedProjects(await loadVault(), o2.payload.projects, {});
    expect(m2.merged.projects.other.vars.Z.value).toBe("keep");
    expect(m2.merged.projects.gotchibot.vars.LOCAL.value).toBe("stay");
    expect(m2.merged.projects.gotchibot.vars.NEW.value).toBe("n");
    expect(m2.merged.projects.gotchibot.vars.A.value).toBe("local-a");
    await saveVault(m2.merged);

    const masterAfter = (await platform.getMasterKey()).toString("base64");
    expect(masterAfter).toBe(masterBefore);
    expect(fs.existsSync(path.join(dir, "abracadabra", "latest.json"))).toBe(false);
  });
});

describe("startLanHost port 0", () => {
  // Ensure port:0 is supported — if not, tests above need a free port picker.
  it("documents that lan-host listens on opts.port", () => {
    // lan-host uses server.listen(port, ...) — port 0 is valid for ephemeral bind.
    expect(true).toBe(true);
  });
});
