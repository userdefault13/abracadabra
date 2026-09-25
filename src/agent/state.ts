import { resolveIdleSeconds } from "./paths.js";
import type { AgentStatusBody } from "./protocol.js";

export type ResolveMasterKeyFn = () => Promise<Buffer>;

/**
 * In-memory unlocked master key + idle lock.
 * Does NOT call authenticate() — unlock only reads the keystore once.
 */
export class AgentState {
  private key: Buffer | null = null;
  private lastActivityAt = 0;
  private idleTimer: NodeJS.Timeout | null = null;
  private readonly idleMs: number;
  private readonly onIdleLock: () => void;
  private readonly resolveMasterKey: ResolveMasterKeyFn;

  constructor(opts?: {
    idleSeconds?: number;
    resolveMasterKey?: ResolveMasterKeyFn;
    onIdleLock?: () => void;
  }) {
    this.idleMs = (opts?.idleSeconds ?? resolveIdleSeconds()) * 1000;
    this.resolveMasterKey =
      opts?.resolveMasterKey ??
      (async () => {
        const { getKeystore } = await import("../platform/index.js");
        const { resolveMasterKey } = await import("../core/masterKey.js");
        return resolveMasterKey(getKeystore());
      });
    this.onIdleLock = opts?.onIdleLock ?? (() => undefined);
  }

  isLocked(): boolean {
    return this.key === null;
  }

  status(): AgentStatusBody {
    if (!this.key) {
      return { locked: true, idleRemainingMs: null };
    }
    const remaining = Math.max(0, this.lastActivityAt + this.idleMs - Date.now());
    return { locked: false, idleRemainingMs: remaining };
  }

  /** Test/inspection: the live key buffer (null when locked). */
  getKeyBufferForTests(): Buffer | null {
    return this.key;
  }

  requireKey(): Buffer {
    if (!this.key) {
      const err = new Error("Agent is locked");
      (err as Error & { code: string }).code = "locked";
      throw err;
    }
    return this.key;
  }

  async unlock(): Promise<void> {
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
    this.touch();
  }

  lock(): void {
    this.clearIdleTimer();
    if (this.key) {
      this.key.fill(0);
      this.key = null;
    }
    this.lastActivityAt = 0;
  }

  /** Reset idle timer — call on vault ops (and after unlock). */
  touch(): void {
    if (!this.key) return;
    this.lastActivityAt = Date.now();
    this.armIdleTimer();
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

  private clearIdleTimer(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
  }
}
