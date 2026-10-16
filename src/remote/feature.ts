/**
 * Remote unlock (hub-held unwrap key + bot leases) is off by default.
 * Enroll + the abra-agent unlock listener (port 7335) require this flag.
 * Explicit CLI (e.g. `abra remote whoami`) may still be invoked by hand.
 */
export function isRemoteUnlockEnabled(): boolean {
  return process.env.ABRA_REMOTE_UNLOCK?.trim() === "1";
}
