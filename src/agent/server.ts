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
  isAgentRequest,
  type AgentOp,
  type AgentRequest,
  type AgentResponse,
  type AgentStatusBody,
  type AgentErrorCode,
} from "./protocol.js";
import {
  decryptVault,
  encryptVault,
  writeEncryptedVaultFile,
  type Vault,
} from "../core/vault.js";
import { vaultFile } from "../core/paths.js";
import { resolveKeystoreBackend } from "../platform/env.js";
import {
  authorizePeer as defaultAuthorizePeer,
  type PeerAuthResult,
  type PeerCheckDeps,
} from "./peer.js";
import {
  GrantStore,
  grantPublicView,
} from "./grants.js";
import {
  startSleepWatch,
  type SleepWatchFactory,
  type SleepWatchHandle,
} from "./sleep-watch.js";

export type { AgentStatusBody };

/** Ops that unlock the in-memory master key, return vault plaintext, or manage grants. */
const SENSITIVE_OPS = new Set<AgentOp>([
  "unlock",
  "unlock.key",
  "vault.load",
  "vault.save",
  "grant.add",
  "grant.list",
  "grant.revoke",
  "grant.check",
]);

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
}

let running: {
  server: net.Server;
  state: AgentState;
  grants: GrantStore;
  socketPath: string;
  vaultPath: () => string;
  keystoreBackend: () => string;
  authorizePeer: AuthorizePeerFn;
  sleepWatch: SleepWatchHandle | null;
} | null = null;

function logOp(op: string, detail?: string): void {
  const extra = detail ? ` ${detail}` : "";
  process.stderr.write(`abra-agent: ${op}${extra}\n`);
}

function fail(id: string, code: AgentErrorCode, error: string): AgentResponse {
  return { v: PROTOCOL_VERSION, id, ok: false, error, code };
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
  // Log op + reason only — never full cmdline or env.
  logOp(op, `forbidden_peer reason=${result.reason}`);
  return fail(
    id,
    "forbidden_peer",
    "Peer is not the abra CLI (client should fall back to direct keystore)",
  );
}

async function handleRequest(
  state: AgentState,
  grants: GrantStore,
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
        // Same-uid status is safe: locked + remaining timers only (no secrets).
        logOp("status");
        return {
          v: PROTOCOL_VERSION,
          id,
          ok: true,
          op: "status",
          status: state.status(),
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
          return { v: PROTOCOL_VERSION, id, ok: true, op: "unlock.key" };
        } finally {
          decoded.fill(0);
        }
      }
      case "lock": {
        // Same-uid lock only reduces access (zeroes the in-memory key + grants).
        logOp("lock");
        state.lock();
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
        const enc = encryptVault(vault, state.requireKey());
        writeEncryptedVaultFile(enc, vaultPath());
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
        if (state.isLocked()) {
          return fail(id, "locked", "Agent is locked");
        }
        const result = grants.check(req.project, req.caller);
        logOp("grant.check", `granted=${result.granted}`);
        return {
          v: PROTOCOL_VERSION,
          id,
          ok: true,
          op: "grant.check",
          granted: result.granted,
          ...(result.grantId ? { grantId: result.grantId } : {}),
          ...(result.remainingMs !== undefined
            ? { remainingMs: result.remainingMs }
            : {}),
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
  const state = new AgentState({
    idleSeconds: opts?.idleSeconds ?? resolveIdleSeconds(),
    maxAgeSeconds: opts?.maxAgeSeconds ?? resolveMaxAgeSeconds(),
    resolveMasterKey: opts?.resolveMasterKey,
    onIdleLock: () => logOp("idle-lock"),
    onMaxAgeLock: () => logOp("max-age-lock"),
    onLock: () => grants.clear(),
  });
  const vaultPath = opts?.vaultPath ?? (() => vaultFile());
  const keystoreBackend = opts?.keystoreBackend ?? (() => resolveKeystoreBackend());
  const peerDeps = opts?.peerCheckDeps;
  const authorize: AuthorizePeerFn =
    opts?.authorizePeer ??
    ((socket) => defaultAuthorizePeer(socket, peerDeps));

  const prevUmask = process.umask(0o077);
  let server: net.Server;
  try {
    server = net.createServer((socket) => {
      attachConnection(state, grants, vaultPath, keystoreBackend, authorize, socket);
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

  running = {
    server,
    state,
    grants,
    socketPath,
    vaultPath,
    keystoreBackend,
    authorizePeer: authorize,
    sleepWatch: sleep,
  };
  logOp("listen", socketPath);
  return { socketPath, state };
}

export async function stopAgent(): Promise<void> {
  if (!running) return;
  const { server, state, socketPath, sleepWatch } = running;
  running = null;
  try {
    sleepWatch?.stop();
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
