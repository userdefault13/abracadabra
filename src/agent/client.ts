import net from "node:net";
import path from "node:path";
import crypto from "node:crypto";
import {
  isAgentEnabled,
  resolveAgentSocketPath,
} from "./paths.js";
import {
  MAX_FRAME_BYTES,
  PROTOCOL_VERSION,
  type AgentRequest,
  type AgentResponse,
  type AgentStatusBody,
  type AgentErrorCode,
  type AgentVaultBinding,
} from "./protocol.js";
import type { Vault } from "../core/vault.js";
import { vaultFile } from "../core/paths.js";
import { resolveKeystoreBackend } from "../platform/env.js";

export class AgentClientError extends Error {
  constructor(
    message: string,
    readonly code: AgentErrorCode | "timeout" | "connect",
  ) {
    super(message);
    this.name = "AgentClientError";
  }
}

export function isAgentUnavailable(err: unknown): boolean {
  if (err instanceof AgentClientError) {
    return (
      err.code === "unavailable" ||
      err.code === "mismatch" ||
      err.code === "forbidden_peer" ||
      err.code === "locked" ||
      err.code === "timeout" ||
      err.code === "connect"
    );
  }
  return false;
}

/** Client-side vault path + keystore binding for agent vault I/O. */
export function clientVaultBinding(): AgentVaultBinding {
  return {
    vaultPath: path.resolve(vaultFile()),
    keystoreBackend: resolveKeystoreBackend(),
  };
}

const DEFAULT_CONNECT_MS = 500;

export interface AgentClientOpts {
  socketPath?: string;
  connectTimeoutMs?: number;
}

function nextId(): string {
  return crypto.randomBytes(8).toString("hex");
}

/**
 * One request/response over the agent unix socket (newline-delimited JSON).
 */
export async function agentRequest(
  req: { id?: string } & (
    | { op: "status" }
    | { op: "unlock" }
    | {
        op: "unlock.key";
        key: string;
        vaultPath?: string;
        keystoreBackend?: string;
      }
    | { op: "lock" }
    | { op: "vault.load"; vaultPath?: string; keystoreBackend?: string }
    | {
        op: "vault.save";
        vault: Vault;
        vaultPath?: string;
        keystoreBackend?: string;
      }
  ),
  opts?: AgentClientOpts,
): Promise<AgentResponse> {
  const socketPath = opts?.socketPath ?? resolveAgentSocketPath();
  const connectTimeoutMs = opts?.connectTimeoutMs ?? DEFAULT_CONNECT_MS;
  const id = req.id ?? nextId();
  const frame = { v: PROTOCOL_VERSION, id, ...req } as AgentRequest;
  const payload = JSON.stringify(frame) + "\n";
  if (Buffer.byteLength(payload, "utf8") > MAX_FRAME_BYTES) {
    throw new AgentClientError("Request frame too large", "oversized");
  }

  return new Promise<AgentResponse>((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath });
    let settled = false;
    let buf = Buffer.alloc(0);

    const finish = (err?: Error, res?: AgentResponse) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.destroy();
      if (err) reject(err);
      else resolve(res!);
    };

    const timer = setTimeout(() => {
      finish(new AgentClientError("Agent connect/read timed out", "timeout"));
    }, connectTimeoutMs);

    socket.on("error", (e) => {
      const msg = e instanceof Error ? e.message : String(e);
      finish(new AgentClientError(msg, "connect"));
    });

    socket.on("connect", () => {
      socket.write(payload, (writeErr) => {
        if (writeErr) {
          finish(
            new AgentClientError(
              writeErr instanceof Error ? writeErr.message : String(writeErr),
              "unavailable",
            ),
          );
        }
      });
    });

    socket.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > MAX_FRAME_BYTES) {
        finish(new AgentClientError("Response frame too large", "oversized"));
        return;
      }
      const nl = buf.indexOf(0x0a);
      if (nl < 0) return;
      const line = buf.subarray(0, nl).toString("utf8");
      try {
        const parsed = JSON.parse(line) as AgentResponse;
        if (parsed && typeof parsed === "object" && parsed.id === id) {
          finish(undefined, parsed);
        } else {
          finish(new AgentClientError("Mismatched response id", "internal"));
        }
      } catch {
        finish(new AgentClientError("Invalid JSON response", "internal"));
      }
    });

    socket.on("end", () => {
      if (!settled) {
        finish(new AgentClientError("Agent closed connection", "unavailable"));
      }
    });
  });
}

export async function agentStatus(opts?: AgentClientOpts): Promise<AgentStatusBody> {
  const res = await agentRequest({ op: "status" }, opts);
  if (!res.ok || res.op !== "status") {
    throw new AgentClientError(
      !res.ok ? res.error : "Unexpected status response",
      !res.ok ? res.code : "internal",
    );
  }
  return res.status;
}

export async function agentUnlock(opts?: AgentClientOpts): Promise<void> {
  const res = await agentRequest({ op: "unlock" }, opts);
  if (!res.ok) {
    throw new AgentClientError(res.error, res.code);
  }
}

/**
 * Push a master key into a passphrase-file agent (`unlock.key`).
 * Caller owns `key` and should zero-fill after this returns.
 * Never logs or echoes the key.
 */
export async function agentUnlockKey(
  key: Buffer,
  opts?: AgentClientOpts & { binding?: AgentVaultBinding },
): Promise<void> {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new AgentClientError("key must be a 32-byte Buffer", "bad_request");
  }
  const binding = opts?.binding ?? clientVaultBinding();
  const res = await agentRequest(
    {
      op: "unlock.key",
      key: key.toString("base64"),
      vaultPath: binding.vaultPath,
      keystoreBackend: binding.keystoreBackend,
    },
    opts,
  );
  if (!res.ok) {
    throw new AgentClientError(res.error, res.code);
  }
}

export async function agentLock(opts?: AgentClientOpts): Promise<void> {
  const res = await agentRequest({ op: "lock" }, opts);
  if (!res.ok) {
    throw new AgentClientError(res.error, res.code);
  }
}

export type VaultLoadResult = { empty: true } | { vault: Vault };

export async function agentVaultLoad(opts?: AgentClientOpts): Promise<VaultLoadResult> {
  const binding = clientVaultBinding();
  const res = await agentRequest({ op: "vault.load", ...binding }, opts);
  if (!res.ok) {
    throw new AgentClientError(res.error, res.code);
  }
  if (res.op !== "vault.load") {
    throw new AgentClientError("Unexpected vault.load response", "internal");
  }
  if ("empty" in res && res.empty) return { empty: true };
  if ("vault" in res) return { vault: res.vault };
  throw new AgentClientError("Malformed vault.load response", "internal");
}

export async function agentVaultSave(
  vault: Vault,
  opts?: AgentClientOpts,
): Promise<void> {
  const binding = clientVaultBinding();
  const res = await agentRequest({ op: "vault.save", vault, ...binding }, opts);
  if (!res.ok) {
    throw new AgentClientError(res.error, res.code);
  }
}

/**
 * Load vault via agent: unlock if locked, then vault.load.
 * Throws AgentClientError — caller should fall back on unavailable/connect/timeout/locked.
 *
 * For passphrase-file agents, bare `unlock` returns `locked` (no prompt). That
 * surfaces as AgentClientError(locked), which isAgentUnavailable treats as
 * fallback-to-direct (caller gets VaultLockedError from the keystore).
 */
export async function loadVaultViaAgent(opts?: AgentClientOpts): Promise<Vault> {
  const empty = async (): Promise<Vault> => {
    const { emptyVault } = await import("../core/vault.js");
    return emptyVault();
  };

  const tryLoad = async (): Promise<VaultLoadResult> => agentVaultLoad(opts);

  const unwrap = async (result: VaultLoadResult): Promise<Vault> => {
    if ("vault" in result) return result.vault;
    return empty();
  };

  try {
    return await unwrap(await tryLoad());
  } catch (e) {
    if (e instanceof AgentClientError && e.code === "locked") {
      await agentUnlock(opts);
      return unwrap(await tryLoad());
    }
    throw e;
  }
}

export async function saveVaultViaAgent(
  vault: Vault,
  opts?: AgentClientOpts,
): Promise<void> {
  try {
    await agentVaultSave(vault, opts);
  } catch (e) {
    if (e instanceof AgentClientError && e.code === "locked") {
      await agentUnlock(opts);
      await agentVaultSave(vault, opts);
      return;
    }
    throw e;
  }
}

/** True when abra vault I/O should attempt the agent first. */
export function shouldTryAgent(): boolean {
  if (!isAgentEnabled()) return false;
  try {
    resolveAgentSocketPath();
    return true;
  } catch {
    return false;
  }
}
