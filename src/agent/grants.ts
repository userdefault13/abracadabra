import crypto from "node:crypto";

/** Min/max TTL for agent-held reveal grants (seconds). Max matches 8h agent max age. */
export const GRANT_TTL_MIN_SECONDS = 60;
export const GRANT_TTL_MAX_SECONDS = 8 * 60 * 60; // 28800

export interface GrantCaller {
  /** Absolute realpath of the caller binary. */
  exe: string;
  /** Device id from stat(exe). */
  dev: number;
  /** Inode from stat(exe). */
  ino: number;
}

export interface Grant {
  id: string;
  project: string;
  caller: GrantCaller;
  createdAt: number;
  expiresAt: number;
}

export interface GrantListItem {
  id: string;
  project: string;
  caller: { exe: string };
  remainingMs: number;
}

export interface GrantCheckResult {
  granted: boolean;
  grantId?: string;
  remainingMs?: number;
}

/**
 * In-memory reveal grants held by abra-agent.
 * Cleared on every lock; never persisted; never extends idle/max-age timers.
 */
export class GrantStore {
  private grants = new Map<string, Grant>();
  private pruneTimer: NodeJS.Timeout | null = null;

  /** Drop all grants (called from AgentState.lock via onLock). */
  clear(): void {
    this.grants.clear();
    this.clearPruneTimer();
  }

  size(): number {
    return this.grants.size;
  }

  add(opts: {
    project: string;
    caller: GrantCaller;
    ttlSeconds: number;
    now?: number;
  }): Grant {
    const ttl = opts.ttlSeconds;
    if (
      !Number.isFinite(ttl) ||
      ttl < GRANT_TTL_MIN_SECONDS ||
      ttl > GRANT_TTL_MAX_SECONDS
    ) {
      const err = new Error(
        `ttlSeconds must be ${GRANT_TTL_MIN_SECONDS}..${GRANT_TTL_MAX_SECONDS}`,
      );
      (err as Error & { code: string }).code = "bad_request";
      throw err;
    }
    const project = opts.project?.trim();
    if (!project) {
      const err = new Error("project is required");
      (err as Error & { code: string }).code = "bad_request";
      throw err;
    }
    const { caller } = opts;
    if (
      !caller ||
      typeof caller.exe !== "string" ||
      !caller.exe ||
      typeof caller.dev !== "number" ||
      typeof caller.ino !== "number" ||
      !Number.isFinite(caller.dev) ||
      !Number.isFinite(caller.ino)
    ) {
      const err = new Error("caller must include exe, dev, and ino");
      (err as Error & { code: string }).code = "bad_request";
      throw err;
    }

    const now = opts.now ?? Date.now();
    const grant: Grant = {
      id: crypto.randomBytes(4).toString("hex"),
      project,
      caller: {
        exe: caller.exe,
        dev: caller.dev,
        ino: caller.ino,
      },
      createdAt: now,
      expiresAt: now + ttl * 1000,
    };
    this.grants.set(grant.id, grant);
    this.armPruneTimer();
    return grant;
  }

  list(now = Date.now()): GrantListItem[] {
    this.pruneExpired(now);
    const out: GrantListItem[] = [];
    for (const g of this.grants.values()) {
      out.push({
        id: g.id,
        project: g.project,
        caller: { exe: g.caller.exe },
        remainingMs: Math.max(0, g.expiresAt - now),
      });
    }
    return out;
  }

  revoke(opts: { id?: string; grantId?: string; all?: boolean }): number {
    if (opts.all === true) {
      const n = this.grants.size;
      this.clear();
      return n;
    }
    const target = opts.grantId ?? opts.id;
    if (typeof target === "string" && target) {
      if (!this.grants.has(target)) return 0;
      this.grants.delete(target);
      this.armPruneTimer();
      return 1;
    }
    const err = new Error("revoke requires id or all:true");
    (err as Error & { code: string }).code = "bad_request";
    throw err;
  }

  check(
    project: string,
    caller: GrantCaller,
    now = Date.now(),
  ): GrantCheckResult {
    this.pruneExpired(now);
    for (const g of this.grants.values()) {
      if (g.project !== project) continue;
      if (g.caller.exe !== caller.exe) continue;
      if (g.caller.dev !== caller.dev) continue;
      if (g.caller.ino !== caller.ino) continue;
      if (g.expiresAt <= now) continue;
      return {
        granted: true,
        grantId: g.id,
        remainingMs: Math.max(0, g.expiresAt - now),
      };
    }
    return { granted: false };
  }

  /** @internal */
  pruneExpired(now = Date.now()): number {
    let n = 0;
    for (const [id, g] of this.grants) {
      if (g.expiresAt <= now) {
        this.grants.delete(id);
        n++;
      }
    }
    if (n > 0) this.armPruneTimer();
    return n;
  }

  private nextExpiryMs(now = Date.now()): number | null {
    let soonest: number | null = null;
    for (const g of this.grants.values()) {
      const rem = g.expiresAt - now;
      if (rem <= 0) continue;
      if (soonest === null || rem < soonest) soonest = rem;
    }
    return soonest;
  }

  private armPruneTimer(): void {
    this.clearPruneTimer();
    const rem = this.nextExpiryMs();
    if (rem === null) return;
    this.pruneTimer = setTimeout(() => {
      this.pruneExpired();
      this.armPruneTimer();
    }, rem);
    this.pruneTimer.unref();
  }

  private clearPruneTimer(): void {
    if (this.pruneTimer) {
      clearTimeout(this.pruneTimer);
      this.pruneTimer = null;
    }
  }
}

/** Public grant shape returned by grant.add (no secrets). */
export function grantPublicView(g: Grant): {
  id: string;
  project: string;
  caller: GrantCaller;
  createdAt: number;
  expiresAt: number;
} {
  return {
    id: g.id,
    project: g.project,
    caller: { ...g.caller },
    createdAt: g.createdAt,
    expiresAt: g.expiresAt,
  };
}
