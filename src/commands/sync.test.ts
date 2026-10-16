import { describe, it, expect, afterEach, vi } from "vitest";
import { PassThrough } from "node:stream";
import type { Vault } from "../core/vault.js";
import { NoTerminalError, promptHidden, setOpenTtyForTests, type TtyHandles } from "../core/prompt.js";
import { generateSyncIdentity, getOrCreateSyncIdentity } from "../sync/identity.js";
import { planPeerUpsert } from "../sync/peers.js";
import { cmdSyncPeers, cmdSyncUnpair, cmdSyncWhoami, defaultSyncDeps, ttyConfirm, type SyncDeps } from "./sync.js";
import { memVault } from "../../test/fixtures/mem-vault.js";

function memDeps(initial?: Vault, confirm = true) {
  const mem = memVault(initial);
  const lines: string[] = [];
  const deps: SyncDeps = {
    ...defaultSyncDeps(),
    authenticate: vi.fn(async () => {}),
    loadVault: mem.loadVault,
    updateVault: mem.updateVault,
    confirm: vi.fn(async () => confirm),
    log: (l) => lines.push(l),
  };
  return { deps, lines, writes: mem.writes, stored: mem.stored };
}

function pairedVault(): Vault {
  const peer = generateSyncIdentity();
  return planPeerUpsert(getOrCreateSyncIdentity({ version: 1, projects: {} }).vault, {
    id: peer.id,
    name: "mini",
    ed25519: peer.ed25519.publicKey,
    x25519: peer.x25519.publicKey,
    role: "receiver",
    address: "100.64.0.2",
  }).vault;
}

function fakeTty(typed: string): TtyHandles {
  const input = new PassThrough() as unknown as TtyHandles["input"];
  const output = new PassThrough();
  setImmediate(() => (input as unknown as PassThrough).write(typed));
  return { input, output, close: () => {} };
}

afterEach(() => {
  setOpenTtyForTests(null);
  vi.unstubAllEnvs();
});

describe("abra sync whoami", () => {
  it("creates the identity once (approval + save), then just prints it", async () => {
    const m = memDeps();
    await cmdSyncWhoami({}, m.deps);
    expect(m.deps.authenticate).toHaveBeenCalledTimes(1);
    expect(m.writes).toHaveBeenCalledTimes(1);
    const id = m.stored().syncIdentity!;
    await cmdSyncWhoami({ json: true }, m.deps);
    expect(m.deps.authenticate).toHaveBeenCalledTimes(1);
    expect(m.writes).toHaveBeenCalledTimes(1);
    const out = m.lines.join("\n");
    expect(out).toContain(id.id);
    expect(out).not.toContain(id.ed25519.privateKey);
    expect(out).not.toContain(id.x25519.privateKey);
  });
});

describe("abra sync peers", () => {
  it("lists names/roles/fingerprints; --json adds public keys only", async () => {
    const v = pairedVault();
    const m = memDeps(v);
    await cmdSyncPeers({}, m.deps);
    const peer = Object.values(v.syncPeers!)[0];
    expect(m.lines.join("\n")).toContain("mini");
    expect(m.lines.join("\n")).toContain(peer.idFingerprint);

    const j = memDeps(v);
    await cmdSyncPeers({ json: true }, j.deps);
    const parsed = JSON.parse(j.lines.join("\n"));
    expect(parsed).toEqual([
      expect.objectContaining({ name: "mini", role: "receiver", ed25519: peer.ed25519, lastAddress: "100.64.0.2" }),
    ]);
    const text = j.lines.join("\n");
    expect(text).not.toContain(v.syncIdentity!.ed25519.privateKey);
    expect(text).not.toContain("privateKey");
  });
});

describe("abra sync unpair", () => {
  it("declined confirm → no approval, no write", async () => {
    const m = memDeps(pairedVault(), false);
    await cmdSyncUnpair("mini", {}, m.deps);
    expect(m.deps.authenticate).not.toHaveBeenCalled();
    expect(m.writes).not.toHaveBeenCalled();
  });

  it("--yes → approval then removal", async () => {
    const m = memDeps(pairedVault());
    await cmdSyncUnpair("mini", { yes: true }, m.deps);
    expect(m.deps.confirm).not.toHaveBeenCalled();
    expect(m.deps.authenticate).toHaveBeenCalledTimes(1);
    expect(m.stored().syncPeers).toEqual({});
    expect(m.stored().syncIdentity).toBeDefined();
  });

  it("unknown peer fails before approval", async () => {
    const m = memDeps(pairedVault());
    await expect(cmdSyncUnpair("nope", { yes: true }, m.deps)).rejects.toThrow(/no paired peer/);
    expect(m.deps.authenticate).not.toHaveBeenCalled();
  });
});

describe("TTY prompts", () => {
  it("ttyConfirm reads y/N from the terminal only", async () => {
    setOpenTtyForTests(() => fakeTty("y\n"));
    expect(await ttyConfirm("? ")).toBe(true);
    setOpenTtyForTests(() => fakeTty("\n"));
    expect(await ttyConfirm("? ")).toBe(false);
    setOpenTtyForTests(() => fakeTty("nope\n"));
    expect(await ttyConfirm("? ")).toBe(false);
    setOpenTtyForTests(() => {
      throw new NoTerminalError();
    });
    await expect(ttyConfirm("? ")).rejects.toBeInstanceOf(NoTerminalError);
  });

  it("the PIN prompt never substitutes the CI headless vault passphrase", async () => {
    vi.stubEnv("ABRA_SKIP_BIOMETRICS", "1");
    vi.stubEnv("ABRA_HEADLESS_PASSPHRASE", "ci-vault-passphrase");
    setOpenTtyForTests(() => fakeTty("654321\r"));
    expect(await promptHidden("PIN: ", process.stderr, { allowHeadless: false })).toBe("654321");
    expect(await promptHidden("Vault passphrase: ")).toBe("ci-vault-passphrase");
    expect(await defaultSyncDeps().promptPin("PIN: ")).toBe("654321");
  });
});
