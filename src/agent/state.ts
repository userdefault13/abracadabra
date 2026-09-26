import { resolveIdleSeconds, resolveMaxAgeSeconds } from "./paths.js";
import type { AgentStatusBody } from "./protocol.js";

export type ResolveMasterKeyFn = () => Promise<Buffer>;

/**
 * In-memory unlocked master key + idle lock + absolute max age.
 * Does NOT call authenticate() — unlock only reads the keystore once
 * (keytar path) or accepts a pushed key (passphrase-file via unlock.key).
 */
export class AgentState {
  private key: Buffer | null = null;
  private lastActivityAt = 0;
  private unlockedAt = 0;
  private idleTimer: NodeJS.Timeout | null = null;
  private maxAgeTimer: NodeJS.Timeout | null = null;
  private readonly idleMs: number;
  private readonly maxAgeMs: number;
  private readonly onIdleLock: () => void;
  private readonly onMaxAgeLock: () => void;
  /** Fired on every lock() — idle, max-age, sleep, explicit, stopAgent. */
  private readonly onLock: () => void;
  private readonly resolveMasterKey: ResolveMasterKeyFn;

  constructor(opts?: {
    idleSeconds?: number;
    maxAgeSeconds?: number;
    resolveMasterKey?: ResolveMasterKeyFn;
    onIdleLock?: () => void;
    onMaxAgeLock?: () => void;
    /** Called whenever lock() runs (clears agent-held grants, etc.). */
    onLock?: () => void;
  }) {
    this.idleMs = (opts?.idleSeconds ?? resolveIdleSeconds()) * 1000;
    this.maxAgeMs = (opts?.maxAgeSeconds ?? resolveMaxAgeSeconds()) * 1000;
    this.resolveMasterKey =
      opts?.resolveMasterKey ??
      (async () => {
        const { getKeystore } = await import("../platform/index.js");
        const { resolveMasterKey } = await import("../core/masterKey.js");
        return resolveMasterKey(getKeystore());
      });
    this.onIdleLock = opts?.onIdleLock ?? (() => undefined);
    this.onMaxAgeLock = opts?.onMaxAgeLock ?? (() => undefined);
    this.onLock = opts?.onLock ?? (() => undefined);
  }

  isLocked(): boolean {
    this.enforceMaxAge();
    return this.key === null;
  }

  status(): AgentStatusBody {
    this.enforceMaxAge();
    if (!this.key) {
      return { locked: true, idleRemainingMs: null, maxAgeRemainingMs: null };
    }
    const now = Date.now();
    const idleRemaining = Math.max(0, this.lastActivityAt + this.idleMs - now);
    const maxAgeRemaining = Math.max(0, this.unlockedAt + this.maxAgeMs - now);
    return {
      locked: false,
      idleRemainingMs: idleRemaining,
      maxAgeRemainingMs: maxAgeRemaining,
    };
  }

  /** Test/inspection: the live key buffer (null when locked). */
  getKeyBufferForTests(): Buffer | null {
    return this.key;
  }

  requireKey(): Buffer {
    this.enforceMaxAge();
    if (!this.key) {
      const err = new Error("Agent is locked");
      (err as Error & { code: string }).code = "locked";
      throw err;
    }
    return this.key;
  }

  async unlock(): Promise<void> {
    this.enforceMaxAge();
    if (this.key) {
      this.touch();
      return;
    }
    const key = await this.resolveMasterKey();
    if (!Buffer.isBuffer(key) || key.length !== 32) {
      throw new Error("Master key must be a 32-byte Buffer");
    }
    // Own a copy so callers can't mutate our in-memory key via the returned buffer.
    this.key = Buffer.from(key);
    this.unlockedAt = Date.now();
    this.touch();
    this.armMaxAgeTimer();
  }

  /**
   * Store a copy of an externally-supplied master key (CLI `unlock.key`).
   * Does not extend/reset absolute max age from prior unlock — this is a fresh unlock.
   */
  unlockWithKey(key: Buffer): void {
    if (!Buffer.isBuffer(key) || key.length !== 32) {
      throw new Error("Master key must be a 32-byte Buffer");
    }
    this.clearIdleTimer();
    this.clearMaxAgeTimer();
    if (this.key) {
      this.key.fill(0);
      this.key = null;
    }
    this.key = Buffer.from(key);
    this.unlockedAt = Date.now();
    this.touch();
    this.armMaxAgeTimer();
  }

  lock(): void {
    this.clearIdleTimer();
    this.clearMaxAgeTimer();
    if (this.key) {
      this.key.fill(0);
      this.key = null;
    }
    this.lastActivityAt = 0;
    this.unlockedAt = 0;
    this.onLock();
  }

  /** Reset idle timer — call on vault ops (and after unlock). Does NOT extend max age. */
  touch(): void {
    if (!this.key) return;
    this.lastActivityAt = Date.now();
    this.armIdleTimer();
  }

  private enforceMaxAge(): void {
    if (!this.key || this.maxAgeMs <= 0) return;
    if (Date.now() >= this.unlockedAt + this.maxAgeMs) {
      this.lock();
      this.onMaxAgeLock();
    }
  }

  private armIdleTimer(): void {
    this.clearIdleTimer();
    if (!this.key || this.idleMs <= 0) return;
    this.idleTimer = setTimeout(() => {
      this.lock();
      this.onIdleLock();
    }, this.idleMs);
    // Don't keep the process alive solely for idle lock.
    this.idleTimer.unref();
  }

  private armMaxAgeTimer(): void {
    this.clearMaxAgeTimer();
    if (!this.key || this.maxAgeMs <= 0) return;
    const remaining = this.unlockedAt + this.maxAgeMs - Date.now();
    if (remaining <= 0) {
      this.lock();
      this.onMaxAgeLock();
      return;
    }
    this.maxAgeTimer = setTimeout(() => {
      this.lock();
      this.onMaxAgeLock();
    }, remaining);
    this.maxAgeTimer.unref();
  }

  private clearIdleTimer(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
  }

  private clearMaxAgeTimer(): void {
    if (this.maxAgeTimer) {
      clearTimeout(this.maxAgeTimer);
      this.maxAgeTimer = null;
    }
  }
}
