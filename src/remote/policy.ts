import {
  DEFAULT_IDLE_SECONDS,
  DEFAULT_MAX_AGE_SECONDS,
  resolveIdleSeconds,
  resolveMaxAgeSeconds,
} from "../agent/paths.js";
import type { UnlockPolicy } from "./wire.js";

/**
 * Relock policy (PR 5): hub may request shorter idle / max-age in the signed
 * unlock response; the receiver applies min(requested, local cap). Local caps
 * default to the agent's idle 15m / max 8h (`ABRA_AGENT_IDLE_SECONDS` /
 * `ABRA_AGENT_MAX_AGE_SECONDS`). A hub can only shorten timers, never lengthen.
 */

export interface UnlockPolicyCaps {
  idleSeconds: number;
  maxAgeSeconds: number;
}

export interface AppliedUnlockPolicy {
  idleSeconds: number;
  maxAgeSeconds: number;
}

/** Local receiver caps — same env knobs as abra-agent. */
export function localUnlockCaps(): UnlockPolicyCaps {
  return {
    idleSeconds: resolveIdleSeconds(),
    maxAgeSeconds: resolveMaxAgeSeconds(),
  };
}

export function defaultUnlockCaps(): UnlockPolicyCaps {
  return {
    idleSeconds: DEFAULT_IDLE_SECONDS,
    maxAgeSeconds: DEFAULT_MAX_AGE_SECONDS,
  };
}

/**
 * Apply hub-requested policy under local caps.
 * Missing fields → local cap. Present fields → min(requested, cap).
 * Rejects non-positive results (malformed / zero timers).
 */
export function clampUnlockPolicy(
  requested: UnlockPolicy,
  caps: UnlockPolicyCaps = localUnlockCaps(),
): AppliedUnlockPolicy {
  if (!Number.isSafeInteger(caps.idleSeconds) || caps.idleSeconds <= 0) {
    throw new Error("invalid local idle cap");
  }
  if (!Number.isSafeInteger(caps.maxAgeSeconds) || caps.maxAgeSeconds <= 0) {
    throw new Error("invalid local max-age cap");
  }

  const idleSeconds =
    requested.idleSeconds === undefined
      ? caps.idleSeconds
      : Math.min(requested.idleSeconds, caps.idleSeconds);
  const maxAgeSeconds =
    requested.maxAgeSeconds === undefined
      ? caps.maxAgeSeconds
      : Math.min(requested.maxAgeSeconds, caps.maxAgeSeconds);

  if (!Number.isSafeInteger(idleSeconds) || idleSeconds <= 0) {
    throw new Error("unlock policy idle must be a positive integer (seconds)");
  }
  if (!Number.isSafeInteger(maxAgeSeconds) || maxAgeSeconds <= 0) {
    throw new Error("unlock policy max-age must be a positive integer (seconds)");
  }

  return { idleSeconds, maxAgeSeconds };
}

/**
 * Parse CLI duration for `--idle` / `--max-age`: `90s`, `30m`, `2h`, or plain seconds.
 * Returns seconds; no grant TTL floor — receiver clamps to its local cap.
 */
export function parsePolicyDuration(raw: string, label: string): number {
  const s = raw.trim().toLowerCase();
  if (!s) throw new Error(`${label} is required`);

  const m = s.match(/^(\d+(?:\.\d+)?)(s|m|h)?$/);
  if (!m) {
    throw new Error(
      `invalid ${label} "${raw}" — use e.g. 90s, 5m, 1h, or plain seconds`,
    );
  }
  const n = Number(m[1]);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`invalid ${label} "${raw}"`);
  }
  const unit = m[2] ?? "s";
  let seconds: number;
  switch (unit) {
    case "s":
      seconds = Math.floor(n);
      break;
    case "m":
      seconds = Math.floor(n * 60);
      break;
    case "h":
      seconds = Math.floor(n * 3600);
      break;
    default:
      throw new Error(`invalid ${label} unit in "${raw}"`);
  }
  if (!Number.isSafeInteger(seconds) || seconds <= 0) {
    throw new Error(`invalid ${label} "${raw}"`);
  }
  return seconds;
}

/** Build a hub-side UnlockPolicy from optional CLI durations (seconds). */
export function buildRequestedPolicy(opts: {
  idleSeconds?: number;
  maxAgeSeconds?: number;
}): UnlockPolicy {
  const out: UnlockPolicy = {};
  if (opts.idleSeconds !== undefined) {
    if (!Number.isSafeInteger(opts.idleSeconds) || opts.idleSeconds <= 0) {
      throw new Error("idle must be a positive integer (seconds)");
    }
    out.idleSeconds = opts.idleSeconds;
  }
  if (opts.maxAgeSeconds !== undefined) {
    if (!Number.isSafeInteger(opts.maxAgeSeconds) || opts.maxAgeSeconds <= 0) {
      throw new Error("max-age must be a positive integer (seconds)");
    }
    out.maxAgeSeconds = opts.maxAgeSeconds;
  }
  return out;
}
