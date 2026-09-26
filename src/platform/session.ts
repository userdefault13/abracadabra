const DEFAULT_TTL_MS = 8 * 60 * 60 * 1000;

let cachedMasterKey: Buffer | null = null;
let unlockExpiresAt = 0;

function ttlMs(): number {
  const raw = process.env.ABRA_UNLOCK_TTL_SECONDS;
  if (!raw) return DEFAULT_TTL_MS;
  const sec = Number(raw);
  if (!Number.isFinite(sec) || sec <= 0) return DEFAULT_TTL_MS;
  return sec * 1000;
}

function zeroAndDrop(): void {
  if (cachedMasterKey) {
    cachedMasterKey.fill(0);
    cachedMasterKey = null;
  }
}

export function isSessionUnlocked(): boolean {
  if (!cachedMasterKey) return false;
  if (Date.now() > unlockExpiresAt) {
    lockSession();
    return false;
  }
  return true;
}

export function getSessionMasterKey(): Buffer | null {
  return isSessionUnlocked() ? cachedMasterKey : null;
}

/**
 * Cache a copy of the master key for the session TTL.
 * The plaintext passphrase is never stored — re-wrap flows must prompt again.
 */
export function unlockSession(masterKey: Buffer): void {
  if (masterKey.length !== 32) throw new Error("Master key must be 32 bytes");
  zeroAndDrop();
  cachedMasterKey = Buffer.from(masterKey);
  unlockExpiresAt = Date.now() + ttlMs();
}

export function lockSession(): void {
  zeroAndDrop();
  unlockExpiresAt = 0;
}

export function sessionUnlockExpiresAt(): number {
  return unlockExpiresAt;
}

/** Test hook */
export function resetSessionForTests(): void {
  lockSession();
}
