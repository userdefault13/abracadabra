import type { SyncIdentity, UnlockWrap, Vault } from "../core/vault.js";
import { appendAuditLog } from "./audit.js";
import { remoteLeaseRevokeViaHttp, type RemoteHttpsJsonFn } from "./hub-client.js";
import {
  deleteHubLeaseRecordsForPeer,
  listHubLeaseRecords,
} from "./hub-leases.js";
import { REMOTE_UNLOCK_PORT } from "./wire.js";

/**
 * Best-effort: push a signed "revoke all" for a peer's device leases, then
 * drop hub registry rows. Used by `abra remote revoke` and `abra sync unpair`.
 * Never logs secrets. If the receiver is unreachable, registry is still cleared
 * and the caller is told — on-disk leases lapse at expiry.
 */

export interface RevokePeerLeasesOpts {
  vault: Vault;
  /** Sync peer name (for logs / audit). */
  peerName: string;
  /** Sync peer identity id. */
  peerSyncId: string;
  unlockWrap?: UnlockWrap;
  /** Peer lastAddress for HTTPS. */
  host?: string;
  base: string;
  now?: () => number;
  request?: RemoteHttpsJsonFn;
  audit?: typeof appendAuditLog;
  log?: (line: string) => void;
  error?: (line: string) => void;
}

export type RevokePeerLeasesResult = {
  /** Hub registry rows removed. */
  registryCleared: number;
  /** Network revoke outcome. */
  network: "ok" | "unreachable" | "skipped" | "failed";
  reason?: string;
  removedOnReceiver?: number;
};

export async function revokePeerLeasesBestEffort(
  opts: RevokePeerLeasesOpts,
): Promise<RevokePeerLeasesResult> {
  const wrap = opts.unlockWrap;
  const hub = opts.vault.syncIdentity;
  const related = listHubLeaseRecords(opts.base).filter(
    (r) =>
      r.peerSyncId === opts.peerSyncId ||
      r.peerName === opts.peerName ||
      (wrap !== undefined && r.peerDeviceId === wrap.deviceId),
  );

  let network: RevokePeerLeasesResult["network"] = "skipped";
  let reason: string | undefined;
  let removedOnReceiver: number | undefined;

  const canNetwork =
    hub &&
    wrap &&
    typeof opts.host === "string" &&
    opts.host.length > 0 &&
    typeof wrap.listenerCert === "string" &&
    wrap.listenerCert.includes("BEGIN CERTIFICATE");

  if (canNetwork) {
    const out = await remoteLeaseRevokeViaHttp({
      host: opts.host!,
      port: REMOTE_UNLOCK_PORT,
      ca: wrap!.listenerCert!,
      hubIdentity: hub as SyncIdentity,
      peerDeviceId: wrap!.deviceId,
      all: true,
      now: opts.now,
      request: opts.request,
    });
    if (out.ok) {
      network = "ok";
      removedOnReceiver = out.removed;
      opts.log?.(
        `revoked ${out.removed} lease(s) on peer "${opts.peerName}"`,
      );
    } else if (out.reason === "unreachable") {
      network = "unreachable";
      reason = "unreachable";
      opts.error?.(
        `peer "${opts.peerName}" unreachable for lease revoke — leases will lapse at expiry`,
      );
    } else {
      network = "failed";
      reason = out.reason;
      opts.error?.(
        `lease revoke to "${opts.peerName}" failed: ${out.reason} — leases will lapse at expiry`,
      );
    }
  } else if (related.length > 0) {
    network = "skipped";
    reason = "no-listener";
    opts.error?.(
      `cannot reach peer "${opts.peerName}" for lease revoke (missing address/cert) — leases will lapse at expiry`,
    );
  }

  const registryCleared = deleteHubLeaseRecordsForPeer(
    {
      peerSyncId: opts.peerSyncId,
      peerName: opts.peerName,
      peerDeviceId: wrap?.deviceId,
    },
    opts.base,
  );

  (opts.audit ?? appendAuditLog)(
    {
      op: "lease-revoke-peer",
      peer: opts.peerName,
      result:
        network === "ok"
          ? "ok"
          : network === "unreachable"
            ? "unreachable"
            : network === "failed"
              ? `failed:${reason ?? "unknown"}`
              : registryCleared > 0
                ? "registry-cleared"
                : "noop",
    },
    { base: opts.base, now: opts.now },
  );

  return { registryCleared, network, reason, removedOnReceiver };
}
