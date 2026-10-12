import { describe, it, expect, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import type { Vault } from "../core/vault.js";
import { AgentInbox } from "../agent/inbox.js";
import { upsertAcceptRule } from "./accept.js";
import { sealForPeer, sealProjects } from "./envelope.js";
import { generateSyncIdentity } from "./identity.js";
import { INBOX_PATH } from "./inbox.js";
import { anchorsFromVault, loadOrCreateInboxTls, syncInboxDir, writeAnchors } from "../core/sync-inbox-store.js";
import { makePair } from "../../test/fixtures/sync-vaults.js";

/**
 * Real HTTPS inbox listener on 127.0.0.1:0 (in-process abra-agent controller)
 * receiving envelopes sealed by a second identity. The listener cert comes from
 * openssl (loadOrCreateInboxTls) — same assumption as the pairing loopback test.
 */

const hasOpenssl = spawnSync("openssl", ["version"], { stdio: "ignore" }).status === 0;

function post(port: number, cert: string, body: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
  const data = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: "127.0.0.1",
        port,
        path: INBOX_PATH,
        method: "POST",
        ca: cert,
        // Self-signed per-device cert pinned via `ca`; its CN is not an IP.
        checkServerIdentity: () => undefined,
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, json: JSON.parse(Buffer.concat(chunks).toString("utf8")) }));
      },
    );
    req.on("error", reject);
    req.end(data);
  });
}

describe.skipIf(!hasOpenssl)("sync inbox — loopback HTTPS", () => {
  const dirs: string[] = [];
  const controllers: AgentInbox[] = [];

  afterEach(async () => {
    await Promise.all(controllers.splice(0).map((c) => c.stop()));
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true, maxRetries: 3 });
  });

  it("queues while locked, applies after unlock, auto-applies when unlocked, rejects forgeries", async () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "abra-inbox-lb-"));
    dirs.push(base);
    const { source, receiver, sourceId, receiverId } = makePair();
    let vault: Vault = upsertAcceptRule(
      { ...receiver, syncInbox: { enabled: true, port: 0, bind: "127.0.0.1" } },
      { from: sourceId.id, projects: "*", auto: true },
    ).vault;
    writeAnchors(base, anchorsFromVault(vault));
    let locked = true;

    const ctl = new AgentInbox({
      base,
      loadUnlockedVault: async () => (locked ? null : structuredClone(vault)),
      saveVault: async (v) => {
        vault = structuredClone(v);
      },
      log: () => {},
    });
    controllers.push(ctl);
    await ctl.start();
    const st = ctl.status();
    expect(st).toMatchObject({ listening: true, bind: "127.0.0.1" });
    const port = st.port!;
    const cert = fs.readFileSync(path.join(syncInboxDir(base), "tls-cert.pem"), "utf8");
    if (process.platform !== "win32") {
      expect(fs.statSync(path.join(syncInboxDir(base), "tls-key.pem")).mode & 0o777).toBe(0o600);
    }
    expect(loadOrCreateInboxTls(base).cert).toBe(cert); // stable per device

    const first = sealForPeer(source, "mini", ["other"]);
    expect(await post(port, cert, first)).toEqual({ status: 202, json: { status: "queued" } });
    expect(vault.projects.other).toBeUndefined();

    locked = false;
    await ctl.onUnlock();
    expect(vault.projects.other).toEqual(source.projects.other);
    expect(ctl.status().queued).toBe(0);

    const second = sealForPeer(source, "mini", ["app"]);
    expect(await post(port, cert, second)).toEqual({ status: 200, json: { status: "applied" } });
    expect(vault.projects.app.vars.A).toEqual(source.projects.app.vars.A);
    expect(vault.projects.app.vars.B.value).toBe("b-local");

    expect(await post(port, cert, second)).toEqual({ status: 409, json: { status: "rejected", reason: "replay" } });
    const forged = sealProjects({ ...generateSyncIdentity(), id: sourceId.id }, {
      id: receiverId.id,
      x25519: receiverId.x25519.publicKey,
    }, { evil: { createdAt: 1, vars: {} } });
    expect(await post(port, cert, forged)).toEqual({ status: 403, json: { status: "rejected", reason: "unauthorized" } });
    expect(vault.projects.evil).toBeUndefined();
  }, 30_000);
});
