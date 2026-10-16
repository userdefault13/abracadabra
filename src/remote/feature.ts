/**
 * Remote unlock (hub-held unwrap key + bot leases) is off by default.
 * Enroll / unlock / lock / disable + the abra-agent listener (port 7335)
 * require this flag. `abra remote whoami` and `status` may still run by hand
 * (status is read-only against local enroll records).
 */
export function isRemoteUnlockEnabled(): boolean {
  return process.env.ABRA_REMOTE_UNLOCK?.trim() === "1";
}
