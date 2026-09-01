const DEFAULT_TTL_MS = 8 * 60 * 60 * 1000;

let cachedMasterKey: Buffer | null = null;
let cachedPassphrase: string | null = null;
let unlockExpiresAt = 0;

function ttlMs(): number {
  const raw = process.env.ABRA_UNLOCK_TTL_SECONDS;
  if (!raw) return DEFAULT_TTL_MS;
  const sec = Number(raw);
  if (!Number.isFinite(sec) || sec <= 0) return DEFAULT_TTL_MS;
  return sec * 1000;
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

export function getSessionPassphrase(): string | null {
  return isSessionUnlocked() ? cachedPassphrase : null;
}

export function unlockSession(masterKey: Buffer, passphrase: string): void {
  cachedMasterKey = masterKey;
  cachedPassphrase = passphrase;
  unlockExpiresAt = Date.now() + ttlMs();
}

export function lockSession(): void {
  cachedMasterKey = null;
  cachedPassphrase = null;
  unlockExpiresAt = 0;
}

export function sessionUnlockExpiresAt(): number {
  return unlockExpiresAt;
}

/** Test hook */
export function resetSessionForTests(): void {
  lockSession();
}
