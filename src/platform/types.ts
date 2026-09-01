export interface AuthRequest {
  reason: string;
  timeoutSeconds?: number;
}

/** Persists the 32-byte vault master key (not per-var secrets). */
export interface PlatformKeystore {
  readonly id: string;
  getOrCreateMasterKey(): Promise<Buffer>;
  storeMasterKey(key: Buffer): Promise<void>;
}

/** Human approval before returning secrets (API, get, MCP, issue keys, …). */
export interface PlatformAuth {
  readonly id: string;
  supportsBiometrics(): boolean;
  authenticate(req: AuthRequest): Promise<void>;
}
