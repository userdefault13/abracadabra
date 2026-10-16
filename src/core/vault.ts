import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { vaultFile } from "./paths.js";
import {
  assertVaultLockHeld,
  currentVaultLockToken,
  isVaultLockHeld,
  withVaultLock,
  type VaultLockOptions,
} from "./vault-lock.js";
import { getKeystore } from "../platform/index.js";
import { resolveMasterKey } from "./masterKey.js";
import {
  AgentClientError,
  isAgentUnavailable,
  loadVaultViaAgent,
  saveVaultViaAgent,
  shouldTryAgent,
} from "../agent/client.js";

export {
  withVaultLock,
  VaultLockNotHeldError,
  VaultLockTimeoutError,
  type VaultLockOptions,
} from "./vault-lock.js";

export interface VarEntry {
  value: string;
  secret: boolean;
  updatedAt: number;
}

export interface Project {
  createdAt: number;
  vars: Record<string, VarEntry>;
}

export interface Connection {
  provider: string;
  label?: string;
  createdAt: number;
  /** Non-secret metadata (key name, org id, scopes…). */
  meta: Record<string, string>;
  /** Credentials, stored like vars (secret flag respected). */
  vars: Record<string, VarEntry>;
}

/** A registered WebAuthn passkey for unlocking the web dash. */
export interface PasskeyCredential {
  /** base64url credential ID */
  id: string;
  /** COSE public key, base64 */
  publicKey: string;
  counter: number;
  /** rpID the credential was registered under (e.g. "localhost") */
  rpId: string;
  label?: string;
  createdAt: number;
}

/**
 * A bearer token for the local HTTP API (POST /secret). Requests carrying a
 * valid key skip the per-use Touch ID prompt — meant for AI agents and
 * long-running scripts. Only a hash is stored; the full key is shown once.
 */
export interface ApiKey {
  id: string; // short hex id, part of the full key
  name: string; // human label, e.g. "opencode-agent"
  keyHash: string; // sha256 hex of the full secret
  prefix: string; // display-safe prefix of the full key
  /** projects this key may read; null = all projects */
  projects: string[] | null;
  createdAt: number;
  expiresAt?: number;
  /** GitHub App installation tokens this key may mint (POST /github/token); absent = none */
  github?: GithubGrant;
}

export type GithubPermissionLevel = "read" | "write";

export interface GithubGrant {
  /** repo names inside the App installation (no owner prefix) */
  repositories: string[];
  /** e.g. { contents: "write", pull_requests: "write" } */
  permissions: Record<string, GithubPermissionLevel>;
}

/**
 * This vault's `abra sync` device identity. Keys are base64 of the raw 32-byte
 * values (Ed25519 seed / X25519 scalar for private keys). Private halves exist
 * only inside the encrypted vault — never exported, synced, or printed.
 */
export interface SyncIdentity {
  id: string;
  createdAt: number;
  ed25519: { publicKey: string; privateKey: string };
  x25519: { publicKey: string; privateKey: string };
}

/** What THE PEER is relative to this vault: "source" pushes to me, "receiver" receives from me. */
export type SyncPeerRole = "source" | "receiver";

export interface SyncPeer {
  name: string;
  idFingerprint: string;
  /** base64 raw 32-byte public keys */
  ed25519: string;
  x25519: string;
  role: SyncPeerRole;
  pairedAt: number;
  lastAddress?: string;
}

/** `abra sync accept` rule for inbound bundles. No matching rule → queue. */
export interface SyncAcceptRule {
  /** Source peer identity id, or "*" for every paired source. */
  from: string;
  projects: string[] | "*";
  auto: boolean;
}

/** `abra sync inbox --enable` settings for the abra-agent receiver listener. */
export interface SyncInboxSettings {
  enabled: boolean;
  /** Explicit listen IP; absent → this machine's Tailscale IPv4 at listener start. */
  bind?: string;
  port: number;
}

export interface Vault {
  version: 1;
  projects: Record<string, Project>;
  connections?: Record<string, Connection>;
  passkeys?: PasskeyCredential[];
  apiKeys?: Record<string, ApiKey>;
  /** Device-local: never leaves this machine (see withoutDeviceLocal). */
  syncIdentity?: SyncIdentity;
  /** Device-local, keyed by peer identity id. */
  syncPeers?: Record<string, SyncPeer>;
  /** Device-local inbound accept policy. */
  syncAccept?: SyncAcceptRule[];
  /** Device-local receiver inbox settings. */
  syncInbox?: SyncInboxSettings;
}

/** Vault fields bound to this machine — stripped from every export, never taken from a peer. */
export const DEVICE_LOCAL_VAULT_FIELDS = ["syncIdentity", "syncPeers", "syncAccept", "syncInbox"] as const;

/** Shallow copy without device-local fields (for bundles, sync bases, restores). */
export function withoutDeviceLocal(vault: Vault): Vault {
  const out: Vault = { ...vault };
  for (const field of DEVICE_LOCAL_VAULT_FIELDS) delete out[field];
  return out;
}

/** `incoming` with device-local fields taken from `local` only (peer's are dropped). */
export function keepDeviceLocal(incoming: Vault, local: Vault): Vault {
  const out = withoutDeviceLocal(incoming);
  return { ...out, ...pickDeviceLocal(local) };
}

function pickDeviceLocal(vault: Vault): Partial<Vault> {
  const out: Partial<Vault> = {};
  if (vault.syncIdentity !== undefined) out.syncIdentity = vault.syncIdentity;
  if (vault.syncPeers !== undefined) out.syncPeers = vault.syncPeers;
  if (vault.syncAccept !== undefined) out.syncAccept = vault.syncAccept;
  if (vault.syncInbox !== undefined) out.syncInbox = vault.syncInbox;
  return out;
}

export function hasDeviceLocal(vault: Vault): boolean {
  return DEVICE_LOCAL_VAULT_FIELDS.some((f) => vault[f] !== undefined);
}

export interface EncryptedFile {
  format: "abracadabra-vault";
  version: 1;
  iv: string;
  tag: string;
  data: string;
}

export function emptyVault(): Vault {
  return { version: 1, projects: {}, connections: {} };
}

export function assertConnection(vault: Vault, provider: string): Connection {
  const conn = vault.connections?.[provider];
  if (!conn) throw new Error(`No connection for "${provider}". Run: abra connect ${provider}`);
  return conn;
}

/** Shared AES-256-GCM encrypt — used by vault I/O and the abra agent. */
export function encryptVault(vault: Vault, key: Buffer): EncryptedFile {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(vault), "utf8");
  const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    format: "abracadabra-vault",
    version: 1,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: data.toString("base64"),
  };
}

/** Encrypt a vault that is leaving this machine (USB/LAN/cartridge bundles). */
export function encryptVaultForExport(vault: Vault, key: Buffer): EncryptedFile {
  return encryptVault(withoutDeviceLocal(vault), key);
}

/** Shared AES-256-GCM decrypt of a vault.enc envelope. */
export function decryptVault(file: unknown, key: Buffer): Vault {
  const f = file as EncryptedFile;
  if (f.format !== "abracadabra-vault") throw new Error("Unrecognized vault file");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(f.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(f.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(f.data, "base64")),
    decipher.final(),
  ]);
  return JSON.parse(plaintext.toString("utf8")) as Vault;
}

const RENAME_RETRY_CODES = new Set(["EPERM", "EBUSY", "EACCES"]);

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** Windows refuses to replace a file another process has open — retry briefly. */
function renameWithRetry(from: string, to: string): void {
  for (let attempt = 0; ; attempt++) {
    try {
      fs.renameSync(from, to);
      return;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code ?? "";
      if (process.platform !== "win32" || !RENAME_RETRY_CODES.has(code) || attempt >= 20) {
        fs.rmSync(from, { force: true });
        throw err;
      }
      sleepSync(Math.min(10 * 2 ** attempt, 200));
    }
  }
}

/**
 * Atomically persist an EncryptedFile to vault.enc (mode 0600). Throws
 * VaultLockNotHeldError unless the vault lock is held by this async call chain
 * or, for abra-agent writes on a client's behalf, by `opts.lockToken`.
 */
export function writeEncryptedVaultFile(
  enc: EncryptedFile,
  file = vaultFile(),
  opts: { lockToken?: string } = {},
): void {
  assertVaultLockHeld(path.dirname(file), opts.lockToken);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(enc, null, 2), { mode: 0o600 });
  renameWithRetry(tmp, file);
}

/** Windows: a reader can hit a sharing error while another process replaces the file. */
function readWithRetry(file: string): string {
  for (let attempt = 0; ; attempt++) {
    try {
      return fs.readFileSync(file, "utf8");
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code ?? "";
      if (process.platform !== "win32" || !RENAME_RETRY_CODES.has(code) || attempt >= 20) throw err;
      sleepSync(Math.min(10 * 2 ** attempt, 200));
    }
  }
}

/** Decrypt vault.enc at `file`; null when it does not exist yet. */
export function readVaultFile(file: string, key: Buffer): Vault | null {
  if (!fs.existsSync(file)) return null;
  const vault = decryptVault(JSON.parse(readWithRetry(file)), key);
  vault.connections ??= {};
  vault.apiKeys ??= {};
  return vault;
}

async function loadVaultDirect(): Promise<Vault> {
  const key = await resolveMasterKey(getKeystore());
  return readVaultFile(vaultFile(), key) ?? emptyVault();
}

async function saveVaultDirect(vault: Vault): Promise<void> {
  const key = await resolveMasterKey(getKeystore());
  const enc = encryptVault(vault, key);
  writeEncryptedVaultFile(enc);
}

export async function loadVault(): Promise<Vault> {
  // Under the vault write lock we must not unlock the agent (may prompt) or
  // fall through to a cold keystore read that prompts — fail fast instead.
  const underLock = isVaultLockHeld();
  if (shouldTryAgent()) {
    try {
      return await loadVaultViaAgent({ allowUnlock: !underLock });
    } catch (e) {
      if (underLock && e instanceof AgentClientError && e.code === "locked") {
        throw new AgentClientError("agent locked during save — rerun", "locked");
      }
      if (!isAgentUnavailable(e)) throw e;
      // no socket / no answer / connect timeout → direct keystore path
    }
  }
  return loadVaultDirect();
}

/**
 * Persist `vault` as-is. Asserts (does not acquire) the vault lock: callers
 * must be inside updateVault()/withVaultLock(), and should prefer updateVault
 * so the vault they write was loaded under the same lock. When abra-agent does
 * the write, the lock token travels with the request and the agent re-checks it.
 */
export async function saveVault(vault: Vault): Promise<void> {
  assertVaultLockHeld();
  if (shouldTryAgent()) {
    try {
      await saveVaultViaAgent(vault, { lockToken: currentVaultLockToken() });
      return;
    } catch (e) {
      // Idle-lock under vault.lock: do not unlock or fall back to the keystore
      // (both can prompt). Fail fast — unlock and rerun outside the lock.
      if (e instanceof AgentClientError && e.code === "locked") throw e;
      if (!isAgentUnavailable(e)) throw e;
    }
  }
  await saveVaultDirect(vault);
}

/** Return from a VaultMutator to skip the write (nothing changed). */
export const VAULT_UNCHANGED: unique symbol = Symbol("vault-unchanged");

/**
 * Receives the vault freshly loaded under the lock. Mutate it in place and
 * return nothing, return a replacement, or return VAULT_UNCHANGED to skip the
 * save. Throwing aborts without writing. Must not prompt or touch the network.
 */
export type VaultMutator = (
  vault: Vault,
) => Vault | void | typeof VAULT_UNCHANGED | Promise<Vault | void | typeof VAULT_UNCHANGED>;

export type UpdateVaultOptions = VaultLockOptions;

/**
 * Read-modify-write vault.enc under the cross-process vault lock: acquire,
 * re-load from disk, apply `mutator`, save atomically, release. Returns the
 * vault as saved (or as loaded, for VAULT_UNCHANGED).
 *
 * Keystore / agent unlock (which may prompt) is resolved by a load before the
 * lock is taken, so the lock is never held across user interaction. If the
 * agent idle-locks between that warm load and the locked save, load/save fail
 * fast with "agent locked during save — rerun" instead of prompting under the
 * lock.
 */
export async function updateVault(mutator: VaultMutator, opts: UpdateVaultOptions = {}): Promise<Vault> {
  if (!isVaultLockHeld(opts.dir)) await loadVault();
  return withVaultLock(async () => {
    const current = await loadVault();
    const out = await mutator(current);
    if (out === VAULT_UNCHANGED) return current;
    const next = out ?? current;
    await saveVault(next);
    return next;
  }, opts);
}

/**
 * abra-agent: read-modify-write `file` with the agent's in-memory key, under
 * the same lock CLI processes use (lockfile beside `file`).
 */
export async function updateVaultFile(
  file: string,
  key: () => Buffer,
  mutator: VaultMutator,
  opts: Omit<VaultLockOptions, "dir"> = {},
): Promise<Vault> {
  return withVaultLock(
    async () => {
      const current = readVaultFile(file, key()) ?? emptyVault();
      const out = await mutator(current);
      if (out === VAULT_UNCHANGED) return current;
      const next = out ?? current;
      writeEncryptedVaultFile(encryptVault(next, key()), file);
      return next;
    },
    { ...opts, dir: path.dirname(file) },
  );
}

/**
 * abra-agent `vault.save`: the client already holds the lock and sent its
 * token, which is verified against the lockfile before writing. Clients that
 * predate the lock send no token; the agent takes the lock for them.
 */
export async function saveVaultFileForClient(
  vault: Vault,
  key: Buffer,
  file: string,
  lockToken: string | undefined,
): Promise<void> {
  const write = () => writeEncryptedVaultFile(encryptVault(vault, key), file, { lockToken });
  if (lockToken !== undefined) write();
  else await withVaultLock(write, { dir: path.dirname(file) });
}

export function assertProject(vault: Vault, name: string): Project {
  const project = vault.projects[name];
  if (!project) throw new Error(`Project not found: ${name}`);
  return project;
}

/** Reserved vault project for the user-funded abra treasury wallet (not founder). */
export const TREASURY_PROJECT = "__abra_treasury__";

/** Projects starting with this prefix are system-managed — not for `abra project new`. */
export const RESERVED_PROJECT_PREFIX = "__abra_";

export function isReservedProjectName(name: string): boolean {
  return name.startsWith(RESERVED_PROJECT_PREFIX);
}

/** Decrypt an envelope that came from outside this machine (usb restore/sync). */
export function decryptEnvelope(
  env: { iv: string; tag: string; data: string },
  key: Buffer,
): Vault {
  return decryptVault({ format: "abracadabra-vault", version: 1, ...env }, key);
}

/**
 * Persist a vault restored from a backup/checkpoint under `masterKey`.
 * Device-local sync identity, peers, accept policy and inbox settings are
 * dropped so a cloned vault never shares an identity with its origin — the
 * user re-pairs after restore. The inbox's public-key mirror goes with them.
 * Must run inside withVaultLock() (asserted); hold it across the master-key
 * swap too, so no writer re-encrypts under the old key in between.
 */
export function writeRestoredVault(vault: Vault, masterKey: Buffer): { droppedSyncPairing: boolean } {
  writeEncryptedVaultFile(encryptVault(withoutDeviceLocal(vault), masterKey));
  fs.rmSync(path.join(path.dirname(vaultFile()), "sync-inbox", "anchors.json"), { force: true });
  return { droppedSyncPairing: hasDeviceLocal(vault) };
}

/** Atomically persist an envelope to VAULT_FILE (usb restore). */
export function writeEncryptedFile(enc: {
  iv: string;
  tag: string;
  data: string;
}): void {
  writeEncryptedVaultFile({
    format: "abracadabra-vault",
    version: 1,
    iv: enc.iv,
    tag: enc.tag,
    data: enc.data,
  });
}
