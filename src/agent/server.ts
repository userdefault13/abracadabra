import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  agentRuntimeDir,
  ensureAgentRuntimeDir,
  resolveAgentSocketPath,
  resolveIdleSeconds,
  resolveMaxAgeSeconds,
} from "./paths.js";
import { AgentState, type ResolveMasterKeyFn } from "./state.js";
import {
  agentRequest,
  agentStatus as clientAgentStatus,
  type AgentClientOpts,
} from "./client.js";
import {
  MAX_FRAME_BYTES,
  PROTOCOL_VERSION,
  SENSITIVE_OPS,
  isAgentRequest,
  type AgentOp,
  type AgentRequest,
  type AgentResponse,
  type AgentStatusBody,
  type AgentInboxStatusBody,
  type AgentErrorCode,
} from "./protocol.js";
import {
  decryptVault,
  readVaultFile,
  saveVaultFileForClient,
  updateVaultFile,
  type Vault,
} from "../core/vault.js";
import { vaultFile } from "../core/paths.js";
import { resolveKeystoreBackend } from "../platform/env.js";
import {
  authorizePeer as defaultAuthorizePeer,
  peerFailureHint,
  resolveAbraCliEntrypoint,
  type PeerAuthResult,
  type PeerCheckDeps,
} from "./peer.js";
import {
  GrantStore,
  grantPublicView,
} from "./grants.js";
import { LeaseStore } from "./lease-store.js";
import { LeaseError } from "../remote/lease.js";
import {
  startSleepWatch,
  type SleepWatchFactory,
  type SleepWatchHandle,
} from "./sleep-watch.js";
import { AgentInbox, type AgentInboxController, type AgentInboxDeps } from "./inbox.js";
import {
  AgentRemoteUnlock,
  type AgentRemoteUnlockController,
  type AgentRemoteUnlockDeps,
} from "./remote-unlock.js";

export type { AgentStatusBody };

export type AuthorizePeerFn = (
  socket: net.Socket,
) => Promise<PeerAuthResult>;

export interface StartAgentOpts {
  socketPath?: string;
  idleSeconds?: number;
  maxAgeSeconds?: number;
  /** Injectable master-key resolution (tests). Default: resolveMasterKey(getKeystore()). */
  resolveMasterKey?: ResolveMasterKeyFn;
  /** Injectable vault.enc path (defaults to vaultFile()). */
  vaultPath?: () => string;
  /** Injectable keystore backend id (defaults to resolveKeystoreBackend()). */
  keystoreBackend?: () => string;
  /**
   * Peer authorization for sensitive ops. Default: Linux ss+/proc check.
   * Tests may inject a stub; non-Linux without an injection always rejects.
   */
  authorizePeer?: AuthorizePeerFn;
  /** Extra deps for the default Linux peer check (tests). */
  peerCheckDeps?: PeerCheckDeps;
  /**
   * Sleep/suspend lock via logind PrepareForSleep.
   * - omit / undefined → start default sleep watch on Linux
   * - `false` → disable
   * - factory → inject for tests
   */
  sleepWatch?: false | SleepWatchFactory;
  /**
   * `abra sync` receiver inbox (listener runs only when enabled + a source is paired).
   * - omit → default controller
   * - `false` → disable
   * - factory → wrap/replace the default deps (tests)
   */
  syncInbox?: false | ((defaults: AgentInboxDeps) => AgentInboxController);
  /**
   * Remote unlock listener (port 7335, Tailscale-only). Off unless
   * ABRA_REMOTE_UNLOCK=1 and enrolled. `false` disables; factory for tests.
   */
  remoteUnlock?: false | ((defaults: AgentRemoteUnlockDeps) => AgentRemoteUnlockController);
}

let running: {
  server: net.Server;
  state: AgentState;
  grants: GrantStore;
  leases: LeaseStore;
  socketPath: string;
  vaultPath: () => string;
  keystoreBackend: () => string;
  authorizePeer: AuthorizePeerFn;
  sleepWatch: SleepWatchHandle | null;
  inbox: AgentInboxController | null;
  remoteUnlock: AgentRemoteUnlockController | null;
} | null = null;

const INBOX_OFF: AgentInboxStatusBody = {
  configured: false,
  enabled: false,
  listening: false,
  bind: null,
  port: null,
  sources: 0,
  queued: 0,
  error: null,
};

function logOp(op: string, detail?: string): void {
  const extra = detail ? ` ${detail}` : "";
  process.stderr.write(`abra-agent: ${op}${extra}\n`);
}

function fail(
  id: string,
  code: AgentErrorCode,
  error: string,
  extra?: { reason?: string; hint?: string },
): AgentResponse {
  return { v: PROTOCOL_VERSION, id, ok: false, error, code, ...extra };
}

/** Strict base64 → exactly 32 bytes. Returns null on any violation. */
function decodeMasterKeyB64(raw: unknown): Buffer | null {
  if (typeof raw !== "string" || !raw) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) return null;
  if (raw.length % 4 !== 0) return null;
  let buf: Buffer;
  try {
    buf = Buffer.from(raw, "base64");
  } catch {
    return null;
  }
  if (buf.length !== 32) return null;
  // Round-trip rejects non-canonical / ignored characters.
  if (buf.toString("base64") !== raw) return null;
  return buf;
}

/** Refuse vault I/O that would touch a different vault / keystore than this agent. */
function checkVaultBinding(
  id: string,
  req: { vaultPath?: string; keystoreBackend?: string },
  agentVaultPath: string,
  agentKeystore: string,
): AgentResponse | null {
  const clientPath =
    typeof req.vaultPath === "string" && req.vaultPath.trim()
      ? path.resolve(req.vaultPath)
      : "";
  const expectedPath = path.resolve(agentVaultPath);
  if (!clientPath || clientPath !== expectedPath) {
    return fail(
      id,
      "mismatch",
      "Vault path does not match this agent (client should fall back to direct keystore)",
    );
  }
  const clientKs =
    typeof req.keystoreBackend === "string" ? req.keystoreBackend : "";
  if (!clientKs || clientKs !== agentKeystore) {
    return fail(
      id,
      "mismatch",
      "Keystore backend does not match this agent (client should fall back to direct keystore)",
    );
  }
  return null;
}

async function requireAbraCliPeer(
  id: string,
  op: AgentOp,
  socket: net.Socket,
  authorize: AuthorizePeerFn,
): Promise<AgentResponse | null> {
  const result = await authorize(socket);
  if (result.ok) return null;
  // Hint uses only the agent's own node path + entrypoint — never peer data.
  const hint = peerFailureHint(result.reason, agentIdentity());
  // Log op + reason only — never full cmdline or env.
  logOp(
    op,
    `forbidden_peer reason=${result.reason}${hint ? ` — ${hint}` : ""}`,
  );
  return fail(
    id,
    "forbidden_peer",
    "Peer is not the abra CLI (client should fall back to direct keystore)",
    { reason: result.reason, ...(hint ? { hint } : {}) },
  );
}

/** This agent's node binary + CLI entrypoint (for exe_mismatch rerun hints). */
let hintIdentity: { execPath: string; cliEntrypoint: string } | null = null;
function agentIdentity(): { execPath: string; cliEntrypoint: string } {
  return (
    hintIdentity ?? {
      execPath: process.execPath,
      cliEntrypoint: resolveAbraCliEntrypoint(),
    }
  );
}

async function handleRequest(
  state: AgentState,
  grants: GrantStore,
  leases: LeaseStore,
  vaultPath: () => string,
  keystoreBackend: () => string,
  authorize: AuthorizePeerFn,
  socket: net.Socket,
  req: AgentRequest,
): Promise<AgentResponse> {
  const { id, op } = req;
  try {
    if (SENSITIVE_OPS.has(op)) {
      const peerErr = await requireAbraCliPeer(id, op, socket, authorize);
      if (peerErr) return peerErr;
    }

    switch (op) {
      case "status": {
        // Same-uid status is safe: locked + timers + node/entry paths (no secrets).
        logOp("status");
        const base = state.status();
        const ident = agentIdentity();
        let nodePath: string | undefined;
        let entryPath: string | undefined;
        try {
          nodePath = fs.realpathSync(ident.execPath);
        } catch {
          nodePath = ident.execPath;
        }
        try {
          entryPath = fs.realpathSync(ident.cliEntrypoint);
        } catch {
          entryPath = ident.cliEntrypoint;
        }
        return {
          v: PROTOCOL_VERSION,
          id,
          ok: true,
          op: "status",
          status: { ...base, nodePath, entryPath },
        };
      }
      case "unlock": {
        // Passphrase-file agents never prompt / never call getOrCreateMasterKey.
        // The CLI pushes the key via unlock.key after a tty passphrase prompt.
        if (keystoreBackend() === "passphrase-file" && state.isLocked()) {
          logOp("unlock", "locked");
          return fail(
            id,
            "locked",
            "agent locked — run: abra unlock (on a terminal)",
          );
        }
        logOp("unlock");
        await state.unlock();
        void running?.inbox?.onUnlock();
        void running?.remoteUnlock?.reconcile();
        return { v: PROTOCOL_VERSION, id, ok: true, op: "unlock" };
      }
      case "unlock.key": {
        const agentKs = keystoreBackend();
        // Binding: must be passphrase-file on both sides and match the agent.
        if (agentKs !== "passphrase-file") {
          return fail(
            id,
            "mismatch",
            "unlock.key requires passphrase-file keystore on the agent",
          );
        }
        const bindErr = checkVaultBinding(id, req, vaultPath(), agentKs);
        if (bindErr) return bindErr;
        if (req.keystoreBackend !== "passphrase-file") {
          return fail(
            id,
            "mismatch",
            "unlock.key requires keystoreBackend passphrase-file",
          );
        }

        const decoded = decodeMasterKeyB64(req.key);
        if (!decoded) {
          return fail(id, "bad_request", "key must be base64-encoded 32 bytes");
        }

        try {
          const file = vaultPath();
          if (fs.existsSync(file)) {
            try {
              const raw = JSON.parse(fs.readFileSync(file, "utf8"));
              decryptVault(raw, decoded);
            } catch {
              decoded.fill(0);
              return fail(id, "bad_request", "key does not decrypt vault");
            }
          }
          state.unlockWithKey(decoded);
          logOp("unlock.key", "ok");
          void running?.inbox?.onUnlock();
          void running?.remoteUnlock?.reconcile();
          return { v: PROTOCOL_VERSION, id, ok: true, op: "unlock.key" };
        } finally {
          decoded.fill(0);
        }
      }
      case "lock": {
        // Same-uid lock only reduces access (zeroes the in-memory key + grants).
        logOp("lock");
        state.lock();
        void running?.remoteUnlock?.reconcile();
        return { v: PROTOCOL_VERSION, id, ok: true, op: "lock" };
      }
      case "vault.load": {
        const bindErr = checkVaultBinding(
          id,
          req,
          vaultPath(),
          keystoreBackend(),
        );
        if (bindErr) return bindErr;
        if (state.isLocked()) {
          return fail(id, "locked", "Agent is locked");
        }
        state.touch();
        logOp("vault.load");
        const file = vaultPath();
        if (!fs.existsSync(file)) {
          return { v: PROTOCOL_VERSION, id, ok: true, op: "vault.load", empty: true };
        }
        const raw = JSON.parse(fs.readFileSync(file, "utf8"));
        const vault = decryptVault(raw, state.requireKey());
        vault.connections ??= {};
        vault.apiKeys ??= {};
        return { v: PROTOCOL_VERSION, id, ok: true, op: "vault.load", vault };
      }
      case "vault.save": {
        const bindErr = checkVaultBinding(
          id,
          req,
          vaultPath(),
          keystoreBackend(),
        );
        if (bindErr) return bindErr;
        if (state.isLocked()) {
          return fail(id, "locked", "Agent is locked");
        }
        state.touch();
        logOp("vault.save");
        const vault = req.vault as Vault;
        await saveVaultFileForClient(vault, state.requireKey(), vaultPath(), req.lockToken);
        void running?.inbox?.onVaultSaved(vault);
        return { v: PROTOCOL_VERSION, id, ok: true, op: "vault.save" };
      }
      case "grant.add": {
        if (state.isLocked()) {
          return fail(id, "locked", "Agent is locked");
        }
        // Grants do not touch()/extend idle or max-age timers.
        try {
          const grant = grants.add({
            project: req.project,
            caller: req.caller,
            ttlSeconds: req.ttlSeconds,
          });
          logOp("grant.add", `project=${req.project}`);
          return {
            v: PROTOCOL_VERSION,
            id,
            ok: true,
            op: "grant.add",
            grant: grantPublicView(grant),
          };
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          const code =
            e && typeof e === "object" && "code" in e && (e as { code: string }).code === "bad_request"
              ? "bad_request"
              : "bad_request";
          return fail(id, code, msg);
        }
      }
      case "grant.list": {
        if (state.isLocked()) {
          return fail(id, "locked", "Agent is locked");
        }
        logOp("grant.list");
        return {
          v: PROTOCOL_VERSION,
          id,
          ok: true,
          op: "grant.list",
          grants: grants.list(),
        };
      }
      case "grant.revoke": {
        if (state.isLocked()) {
          return fail(id, "locked", "Agent is locked");
        }
        try {
          const revoked = grants.revoke({
            grantId: req.grantId,
            all: req.all,
            id: req.grantId,
          });
          logOp("grant.revoke", `n=${revoked}`);
          return {
            v: PROTOCOL_VERSION,
            id,
            ok: true,
            op: "grant.revoke",
            revoked,
          };
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          return fail(id, "bad_request", msg);
        }
      }
      case "grant.check": {
        // In-memory grants require unlock. Bot leases survive lock — check them
        // when locked, or as a fallback when no grant matches.
        if (!state.isLocked()) {
          const result = grants.check(req.project, req.caller);
          if (result.granted) {
            logOp("grant.check", `granted=${result.granted}`);
            return {
              v: PROTOCOL_VERSION,
              id,
              ok: true,
              op: "grant.check",
              granted: true,
              ...(result.grantId ? { grantId: result.grantId } : {}),
              ...(result.remainingMs !== undefined
                ? { remainingMs: result.remainingMs }
                : {}),
            };
          }
        }
        const lease = leases.check(req.project, req.caller);
        logOp("grant.check", `granted=${lease.granted}${lease.granted ? " via=lease" : ""}`);
        return {
          v: PROTOCOL_VERSION,
          id,
          ok: true,
          op: "grant.check",
          granted: lease.granted,
          ...(lease.leaseId ? { grantId: lease.leaseId } : {}),
          ...(lease.remainingMs !== undefined
            ? { remainingMs: lease.remainingMs }
            : {}),
        };
      }
      case "lease.reveal": {
        // Serves leased project secrets even while the vault is locked.
        try {
          const revealed = leases.reveal(req.project, req.caller);
          const keys = req.keys;
          const vars: Record<string, string> = {};
          if (keys && keys.length > 0) {
            for (const k of keys) {
              const entry = revealed.vars[k];
              if (!entry) {
                return fail(id, "bad_request", `var not in lease: ${k}`);
              }
              vars[k] = entry.value;
            }
          } else {
            for (const [k, entry] of Object.entries(revealed.vars)) {
              vars[k] = entry.value;
            }
          }
          logOp("lease.reveal", `project=${req.project} leaseId=${revealed.leaseId}`);
          return {
            v: PROTOCOL_VERSION,
            id,
            ok: true,
            op: "lease.reveal",
            leaseId: revealed.leaseId,
            project: revealed.project,
            vars,
            remainingMs: revealed.remainingMs,
          };
        } catch (e) {
          if (e instanceof LeaseError) {
            const code =
              e.reason === "disabled" || e.reason === "not-enrolled"
                ? "unavailable"
                : "bad_request";
            logOp("lease.reveal", `result=${e.reason}`);
            return fail(id, code, e.message);
          }
          const msg = e instanceof Error ? e.message : String(e);
          return fail(id, "bad_request", msg);
        }
      }
      case "inbox.status": {
        // Settings + counts only (no vault data) — same-uid like status.
        return {
          v: PROTOCOL_VERSION,
          id,
          ok: true,
          op: "inbox.status",
          inbox: running?.inbox?.status() ?? INBOX_OFF,
        };
      }
      default:
        return fail(id, "bad_request", "Unknown op");
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    // Unlock / resolveMasterKey failures → unavailable so clients fall back
    // to the direct keystore path (never mint via agent on keyring lock).
    let code: AgentErrorCode = "internal";
    if (
      e &&
      typeof e === "object" &&
      "code" in e &&
      (e as { code: string }).code === "locked"
    ) {
      code = "locked";
    } else if (op === "unlock" || op === "unlock.key") {
      code = op === "unlock" ? "unavailable" : "bad_request";
    }
    logOp(op, `error=${code}`);
    return fail(id, code, msg);
  }
}

function attachConnection(
  state: AgentState,
  grants: GrantStore,
  leases: LeaseStore,
  vaultPath: () => string,
  keystoreBackend: () => string,
  authorize: AuthorizePeerFn,
  socket: net.Socket,
): void {
  let buf = Buffer.alloc(0);
  let closed = false;

  const reply = (res: AgentResponse) => {
    if (closed) return;
    const line = JSON.stringify(res) + "\n";
    if (Buffer.byteLength(line, "utf8") > MAX_FRAME_BYTES) {
      socket.write(JSON.stringify(fail(res.id, "oversized", "Response too large")) + "\n");
      return;
    }
    socket.write(line);
  };

  socket.on("data", (chunk: Buffer) => {
    if (closed) return;
    buf = Buffer.concat([buf, chunk]);
    if (buf.length > MAX_FRAME_BYTES) {
      reply(fail("?", "oversized", "Request frame too large"));
      socket.destroy();
      return;
    }
    let nl: number;
    while ((nl = buf.indexOf(0x0a)) >= 0) {
      const line = buf.subarray(0, nl).toString("utf8");
      buf = buf.subarray(nl + 1);
      if (!line.trim()) continue;
      let raw: unknown;
      try {
        raw = JSON.parse(line);
      } catch {
        reply(fail("?", "bad_request", "Invalid JSON"));
        continue;
      }
      if (!isAgentRequest(raw)) {
        const id =
          raw && typeof raw === "object" && typeof (raw as { id?: unknown }).id === "string"
            ? (raw as { id: string }).id
            : "?";
        reply(fail(id, "bad_request", "Invalid request"));
        continue;
      }
      void handleRequest(
        state,
        grants,
        leases,
        vaultPath,
        keystoreBackend,
        authorize,
        socket,
        raw,
      ).then(reply);
    }
  });

  socket.on("error", () => {
    closed = true;
  });
  socket.on("close", () => {
    closed = true;
  });
}

/** Probe whether another agent is already answering on this socket. */
async function probeExistingAgent(socketPath: string): Promise<boolean> {
  try {
    const res = await agentRequest(
      { op: "status" },
      { socketPath, connectTimeoutMs: 300 },
    );
    return res.ok === true;
  } catch {
    return false;
  }
}

/**
 * Start the per-user abra agent (unix socket). Holds the master key in memory
 * after unlock; does not call authenticate() / PolKit.
 *
 * Sensitive ops (`unlock`, `unlock.key`, `vault.load`, `vault.save`,
 * `grant.*`) require an abra CLI peer (Linux ss+/proc check; fail closed on
 * non-Linux / ambiguity).
 *
 * A fresh process always starts locked (no key persistence across reboot).
 * Grants live only in agent memory and are cleared on every lock.
 *
 * If `abra sync inbox --enable` was run and a source peer is paired, the agent
 * also runs the HTTPS sync inbox (see src/agent/inbox.ts); it keeps queueing
 * while locked and applies auto-accepted bundles after unlock.
 */
export async function startAgent(opts?: StartAgentOpts): Promise<{
  socketPath: string;
  state: AgentState;
}> {
  if (running) {
    throw new Error("abra-agent already running in this process");
  }

  const socketPath = opts?.socketPath ?? resolveAgentSocketPath();
  const dir = agentRuntimeDir(socketPath);
  ensureAgentRuntimeDir(dir);

  if (fs.existsSync(socketPath)) {
    const alive = await probeExistingAgent(socketPath);
    if (alive) {
      throw new Error("abra-agent already running");
    }
    fs.unlinkSync(socketPath);
  }

  const grants = new GrantStore();
  const vaultPath = opts?.vaultPath ?? (() => vaultFile());
  const leaseBase = () => path.dirname(vaultPath());
  const leases = new LeaseStore({
    base: leaseBase(),
    log: (line) => logOp(line),
  });
  const state = new AgentState({
    idleSeconds: opts?.idleSeconds ?? resolveIdleSeconds(),
    maxAgeSeconds: opts?.maxAgeSeconds ?? resolveMaxAgeSeconds(),
    resolveMasterKey: opts?.resolveMasterKey,
    onIdleLock: () => logOp("idle-lock"),
    onMaxAgeLock: () => logOp("max-age-lock"),
    onLock: () => grants.clear(), // leases intentionally survive lock
  });
  const keystoreBackend = opts?.keystoreBackend ?? (() => resolveKeystoreBackend());
  const peerDeps = opts?.peerCheckDeps;
  hintIdentity = {
    execPath: peerDeps?.execPath ?? process.execPath,
    cliEntrypoint: peerDeps?.cliEntrypoint ?? resolveAbraCliEntrypoint(),
  };
  const authorize: AuthorizePeerFn =
    opts?.authorizePeer ??
    ((socket) => defaultAuthorizePeer(socket, peerDeps));

  const prevUmask = process.umask(0o077);
  let server: net.Server;
  try {
    server = net.createServer((socket) => {
      attachConnection(state, grants, leases, vaultPath, keystoreBackend, authorize, socket);
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, () => {
        server.removeListener("error", reject);
        try {
          fs.chmodSync(socketPath, 0o600);
        } catch {
          /* best-effort */
        }
        resolve();
      });
    });
  } finally {
    process.umask(prevUmask);
  }

  let sleep: SleepWatchHandle | null = null;
  if (opts?.sleepWatch === false) {
    sleep = null;
  } else if (typeof opts?.sleepWatch === "function") {
    sleep = opts.sleepWatch({
      onSleep: () => {
        state.lock();
        logOp("sleep-lock");
      },
    });
  } else {
    sleep = startSleepWatch({
      onSleep: () => {
        state.lock();
        logOp("sleep-lock");
      },
    });
  }

  let inbox: AgentInboxController | null = null;
  if (opts?.syncInbox !== false) {
    const defaults: AgentInboxDeps = {
      base: path.dirname(vaultPath()),
      loadUnlockedVault: async () => {
        if (state.isLocked()) return null;
        return readVaultFile(vaultPath(), state.requireKey());
      },
      updateVault: (mutator) => updateVaultFile(vaultPath(), () => state.requireKey(), mutator),
      log: (detail) => logOp("sync-inbox", detail),
    };
    inbox = typeof opts?.syncInbox === "function" ? opts.syncInbox(defaults) : new AgentInbox(defaults);
  }

  let remoteUnlock: AgentRemoteUnlockController | null = null;
  if (opts?.remoteUnlock !== false) {
    const defaults: AgentRemoteUnlockDeps = {
      base: path.dirname(vaultPath()),
      state,
      vaultPath,
      log: (detail) => logOp("remote-unlock", detail),
      leaseStore: leases,
      onUnlocked: () => {
        void running?.inbox?.onUnlock();
      },
    };
    remoteUnlock =
      typeof opts?.remoteUnlock === "function"
        ? opts.remoteUnlock(defaults)
        : new AgentRemoteUnlock(defaults);
  }

  running = {
    server,
    state,
    grants,
    leases,
    socketPath,
    vaultPath,
    keystoreBackend,
    authorizePeer: authorize,
    sleepWatch: sleep,
    inbox,
    remoteUnlock,
  };
  await inbox?.start();
  await remoteUnlock?.start();
  logOp("listen", socketPath);
  return { socketPath, state };
}

export async function stopAgent(): Promise<void> {
  if (!running) return;
  const { server, state, socketPath, sleepWatch, inbox, remoteUnlock } = running;
  running = null;
  try {
    sleepWatch?.stop();
  } catch {
    /* ignore */
  }
  try {
    await remoteUnlock?.stop();
  } catch {
    /* ignore */
  }
  try {
    await inbox?.stop();
  } catch {
    /* ignore */
  }
  state.lock();
  await new Promise<void>((resolve) => {
    server.close(() => resolve());
  });
  try {
    if (fs.existsSync(socketPath)) fs.unlinkSync(socketPath);
  } catch {
    /* ignore */
  }
  logOp("stop");
}

/** Lock the in-process agent (or ask a sibling over the socket). */
export async function lockAgent(): Promise<void> {
  if (running) {
    running.state.lock();
    logOp("lock");
    return;
  }
  const { agentLock } = await import("./client.js");
  await agentLock();
}

/** Status of the in-process agent, else probe the socket. */
export async function agentStatus(opts?: AgentClientOpts): Promise<AgentStatusBody> {
  if (running) return running.state.status();
  return clientAgentStatus(opts);
}

/** @internal */
export function getRunningAgentForTests(): typeof running {
  return running;
}

/** Stop the agent (lock + remove socket) on SIGTERM/SIGINT/SIGHUP. */
export function installSignalHandlers(): void {
  const shutdown = async (sig: string) => {
    logOp("signal", sig);
    try {
      await stopAgent();
    } finally {
      process.exit(0);
    }
  };
  for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
    process.on(sig, () => {
      void shutdown(sig);
    });
  }
}

function isMainModule(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(path.resolve(entry)).href;
  } catch {
    return false;
  }
}

if (isMainModule()) {
  installSignalHandlers();
  startAgent()
    .then(({ socketPath }) => {
      logOp("ready", socketPath);
    })
    .catch((e) => {
      process.stderr.write(
        `abra-agent: failed to start: ${e instanceof Error ? e.message : String(e)}\n`,
      );
      process.exit(1);
    });
}
