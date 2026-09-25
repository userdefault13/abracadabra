import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  agentRuntimeDir,
  ensureAgentRuntimeDir,
  resolveAgentSocketPath,
  resolveIdleSeconds,
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

export type { AgentStatusBody };

export interface StartAgentOpts {
  socketPath?: string;
  idleSeconds?: number;
  /** Injectable master-key resolution (tests). Default: resolveMasterKey(getKeystore()). */
  resolveMasterKey?: ResolveMasterKeyFn;
  /** Injectable vault.enc path (defaults to vaultFile()). */
  vaultPath?: () => string;
}

let running: {
  server: net.Server;
  state: AgentState;
  socketPath: string;
  vaultPath: () => string;
} | null = null;

function logOp(op: string, detail?: string): void {
  const extra = detail ? ` ${detail}` : "";
  process.stderr.write(`abra-agent: ${op}${extra}\n`);
}

function fail(id: string, code: AgentErrorCode, error: string): AgentResponse {
  return { v: PROTOCOL_VERSION, id, ok: false, error, code };
}

async function handleRequest(
  state: AgentState,
  vaultPath: () => string,
  req: AgentRequest,
): Promise<AgentResponse> {
  const { id, op } = req;
  try {
    switch (op) {
      case "status": {
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
        logOp("unlock");
        await state.unlock();
        return { v: PROTOCOL_VERSION, id, ok: true, op: "unlock" };
      }
      case "lock": {
        logOp("lock");
        state.lock();
        return { v: PROTOCOL_VERSION, id, ok: true, op: "lock" };
      }
      case "vault.load": {
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
      default:
        return fail(id, "bad_request", "Unknown op");
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const code: AgentErrorCode =
      e && typeof e === "object" && "code" in e && (e as { code: string }).code === "locked"
        ? "locked"
        : "internal";
    logOp(op, `error=${code}`);
    return fail(id, code, msg);
  }
}

function attachConnection(
  state: AgentState,
  vaultPath: () => string,
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
      void handleRequest(state, vaultPath, raw).then(reply);
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

  const state = new AgentState({
    idleSeconds: opts?.idleSeconds ?? resolveIdleSeconds(),
    resolveMasterKey: opts?.resolveMasterKey,
    onIdleLock: () => logOp("idle-lock"),
  });
  const vaultPath = opts?.vaultPath ?? (() => vaultFile());

  const prevUmask = process.umask(0o077);
  let server: net.Server;
  try {
    server = net.createServer((socket) => {
      attachConnection(state, vaultPath, socket);
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

  running = { server, state, socketPath, vaultPath };
  logOp("listen", socketPath);
  return { socketPath, state };
}

export async function stopAgent(): Promise<void> {
  if (!running) return;
  const { server, state, socketPath } = running;
  running = null;
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

function installSignalHandlers(): void {
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
