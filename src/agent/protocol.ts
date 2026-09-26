import type { Vault } from "../core/vault.js";

/** Protocol version — bump when request/response shapes change incompatibly. */
export const PROTOCOL_VERSION = 1 as const;

/** Max NDJSON frame size (bytes). Vault JSON must fit under this. */
export const MAX_FRAME_BYTES = 8 * 1024 * 1024;

export type AgentOp =
  | "status"
  | "unlock"
  | "unlock.key"
  | "lock"
  | "vault.load"
  | "vault.save";

export interface AgentStatusBody {
  locked: boolean;
  /** Milliseconds until idle lock; null when locked or no idle timer. */
  idleRemainingMs: number | null;
  /** Milliseconds until absolute max-age lock; null when locked. */
  maxAgeRemainingMs: number | null;
}

export type AgentErrorCode =
  | "locked"
  | "unavailable"
  | "mismatch"
  | "forbidden_peer"
  | "bad_request"
  | "oversized"
  | "internal"
  | "already_running";

/** Vault I/O binding — client must match the agent's vault path + keystore. */
export interface AgentVaultBinding {
  /** Absolute path to the client's vault.enc (path.resolve(vaultFile())). */
  vaultPath: string;
  /** Client's resolveKeystoreBackend() result. */
  keystoreBackend: string;
}

export type AgentRequest =
  | { v: typeof PROTOCOL_VERSION; id: string; op: "status" }
  | { v: typeof PROTOCOL_VERSION; id: string; op: "unlock" }
  | {
      v: typeof PROTOCOL_VERSION;
      id: string;
      op: "unlock.key";
      /** Base64-encoded 32-byte master key. Never echoed in responses. */
      key: string;
      vaultPath?: string;
      keystoreBackend?: string;
    }
  | { v: typeof PROTOCOL_VERSION; id: string; op: "lock" }
  | {
      v: typeof PROTOCOL_VERSION;
      id: string;
      op: "vault.load";
      vaultPath?: string;
      keystoreBackend?: string;
    }
  | {
      v: typeof PROTOCOL_VERSION;
      id: string;
      op: "vault.save";
      vault: Vault;
      vaultPath?: string;
      keystoreBackend?: string;
    };

export type AgentResponse =
  | {
      v: typeof PROTOCOL_VERSION;
      id: string;
      ok: true;
      op: "status";
      status: AgentStatusBody;
    }
  | { v: typeof PROTOCOL_VERSION; id: string; ok: true; op: "unlock" }
  | { v: typeof PROTOCOL_VERSION; id: string; ok: true; op: "unlock.key" }
  | { v: typeof PROTOCOL_VERSION; id: string; ok: true; op: "lock" }
  | {
      v: typeof PROTOCOL_VERSION;
      id: string;
      ok: true;
      op: "vault.load";
      vault: Vault;
    }
  | {
      v: typeof PROTOCOL_VERSION;
      id: string;
      ok: true;
      op: "vault.load";
      empty: true;
    }
  | { v: typeof PROTOCOL_VERSION; id: string; ok: true; op: "vault.save" }
  | {
      v: typeof PROTOCOL_VERSION;
      id: string;
      ok: false;
      error: string;
      code: AgentErrorCode;
    };

export function isAgentRequest(raw: unknown): raw is AgentRequest {
  if (!raw || typeof raw !== "object") return false;
  const r = raw as Record<string, unknown>;
  if (r.v !== PROTOCOL_VERSION) return false;
  if (typeof r.id !== "string" || !r.id) return false;
  if (typeof r.op !== "string") return false;
  switch (r.op) {
    case "status":
    case "unlock":
    case "lock":
    case "vault.load":
      return true;
    case "unlock.key":
      return typeof r.key === "string";
    case "vault.save":
      return r.vault !== undefined && typeof r.vault === "object";
    default:
      return false;
  }
}
