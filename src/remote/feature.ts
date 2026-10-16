/**
 * Remote unlock (hub-held unwrap key + bot leases) is off by default.
 * Nothing auto-starts; later PRs gate listeners / unlock on this flag.
 * Explicit CLI (e.g. `abra remote whoami`) may still be invoked by hand.
 */
export function isRemoteUnlockEnabled(): boolean {
  return process.env.ABRA_REMOTE_UNLOCK?.trim() === "1";
}
