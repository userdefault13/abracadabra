export interface AuthRequest {
  reason: string;
  timeoutSeconds?: number;
}

export type KeystoreErrorKind =
  | "not_found"
  | "locked"
  | "denied"
  | "unavailable"
  | "mismatch";

/** Typed failure from a keystore backend that supports getMasterKey. */
export class KeystoreError extends Error {
  constructor(
    readonly kind: KeystoreErrorKind,
    message: string,
    readonly hint?: string,
  ) {
    super(message);
    this.name = "KeystoreError";
  }
}

/** Persists the 32-byte vault master key (not per-var secrets). */
export interface PlatformKeystore {
  readonly id: string;
  getOrCreateMasterKey(): Promise<Buffer>;
  storeMasterKey(key: Buffer): Promise<void>;
  /** Optional: health check for the backend. */
  probe?(): Promise<{ ok: boolean; detail?: string }>;
  /**
   * Optional: read the master key without minting.
   * Throws KeystoreError — only kind `not_found` may trigger minting (and only when no vault exists).
   */
  getMasterKey?(): Promise<Buffer>;
  /** Optional: mint and store a new master key (must refuse if one already exists). */
  createMasterKey?(): Promise<Buffer>;
  /** Optional: delete the stored master key. */
  deleteMasterKey?(): Promise<void>;
}

/** Human approval before returning secrets (API, get, MCP, issue keys, …). */
export interface PlatformAuth {
  readonly id: string;
  supportsBiometrics(): boolean;
  authenticate(req: AuthRequest): Promise<void>;
}
