/**
 * Single-use nonce cache for remote-unlock challenge/response.
 * Pending entries hold the challenge ephemeral private key until the hub replies
 * (or the entry expires). Used nonces reject replays.
 *
 * In-memory only — agent restart clears state (fail closed: fresh challenges).
 */

const CHALLENGE_NONCE_BYTES = 32;

export interface PendingChallenge {
  /** Receiver ephemeral X25519 private key (PKCS8/JWK KeyObject material as raw d). */
  ephPrivateRaw: Buffer;
  /** Receiver ephemeral X25519 public key (base64 raw 32). */
  ephPublic: string;
  deviceId: string;
  createdAt: number;
}

export class NonceCache {
  private pending = new Map<string, PendingChallenge>();
  private used = new Map<string, number>();

  constructor(
    private readonly opts: {
      /** How long a challenge stays redeemable. */
      pendingTtlMs: number;
      /** How long used nonces are remembered for replay rejection. */
      usedRetentionMs: number;
      maxPending: number;
      maxUsed: number;
    } = {
      pendingTtlMs: 60_000,
      usedRetentionMs: 5 * 60_000,
      maxPending: 256,
      maxUsed: 4096,
    },
  ) {}

  static nonceKey(nonceB64: string): string {
    return Buffer.from(nonceB64, "base64").toString("hex");
  }

  prune(now: number): void {
    for (const [k, p] of this.pending) {
      if (now - p.createdAt >= this.opts.pendingTtlMs) {
        p.ephPrivateRaw.fill(0);
        this.pending.delete(k);
      }
    }
    for (const [k, at] of this.used) {
      if (now - at >= this.opts.usedRetentionMs) this.used.delete(k);
    }
    while (this.pending.size > this.opts.maxPending) {
      const first = this.pending.keys().next().value;
      if (first === undefined) break;
      const p = this.pending.get(first);
      p?.ephPrivateRaw.fill(0);
      this.pending.delete(first);
    }
    while (this.used.size > this.opts.maxUsed) {
      const first = this.used.keys().next().value;
      if (first === undefined) break;
      this.used.delete(first);
    }
  }

  /** Store a fresh challenge. Rejects if nonce already pending or used. */
  addPending(nonceB64: string, entry: PendingChallenge, now: number): boolean {
    this.prune(now);
    const key = NonceCache.nonceKey(nonceB64);
    if (this.pending.has(key) || this.used.has(key)) return false;
    if (Buffer.from(nonceB64, "base64").length !== CHALLENGE_NONCE_BYTES) return false;
    this.pending.set(key, entry);
    return true;
  }

  isUsed(nonceB64: string, now: number): boolean {
    this.prune(now);
    return this.used.has(NonceCache.nonceKey(nonceB64));
  }

  /**
   * Take a pending challenge (removes it). Returns null if missing/expired.
   * Caller must zero `ephPrivateRaw` after use.
   */
  takePending(nonceB64: string, now: number): PendingChallenge | null {
    this.prune(now);
    const key = NonceCache.nonceKey(nonceB64);
    const entry = this.pending.get(key);
    if (!entry) return null;
    this.pending.delete(key);
    return entry;
  }

  markUsed(nonceB64: string, now: number): void {
    this.prune(now);
    this.used.set(NonceCache.nonceKey(nonceB64), now);
  }

  /** Test helper — zero all pending private keys. */
  clear(): void {
    for (const p of this.pending.values()) p.ephPrivateRaw.fill(0);
    this.pending.clear();
    this.used.clear();
  }

  get pendingCount(): number {
    return this.pending.size;
  }

  get usedCount(): number {
    return this.used.size;
  }
}
