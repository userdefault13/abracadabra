import https from "node:https";
import type { SyncIdentity, UnlockWrap } from "../core/vault.js";
import type { EnrollOffer } from "./enroll-seal.js";
import type { UnlockHttpResponse } from "./listener.js";
import {
  ENROLL_PATH,
  LOCK_PATH,
  STATUS_PATH,
  UNLOCK_PATH,
  buildLockRequest,
  buildUnlockResponse,
  parseUnlockWireMessage,
  type UnlockChallenge,
  type UnlockPolicy,
  type UnlockResponse,
} from "./wire.js";

/**
 * Hub-side HTTP clients for remote unlock / lock / status / enroll (CLI).
 * Never logs or returns W / master-key material.
 */

export interface RemoteHttpPeer {
  host: string;
  port: number;
  /** PEM of the receiver listener cert (transport only). */
  ca: string;
}

export type RemoteHttpsJsonFn = (opts: {
  host: string;
  port: number;
  /** PEM CA; omit / empty only for first enroll (TOFU — authenticity is Ed25519 on the offer). */
  ca?: string;
  path: string;
  body: unknown;
}) => Promise<{ status: number; json: UnlockHttpResponse }>;

async function unlockHttpsJson(opts: {
  host: string;
  port: number;
  ca?: string;
  path: string;
  body: unknown;
}): Promise<{ status: number; json: UnlockHttpResponse }> {
  const data = JSON.stringify(opts.body);
  const hasCa = typeof opts.ca === "string" && opts.ca.includes("BEGIN CERTIFICATE");
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: opts.host,
        port: opts.port,
        path: opts.path,
        method: "POST",
        ...(hasCa
          ? { ca: opts.ca, checkServerIdentity: () => undefined }
          : { rejectUnauthorized: false }),
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(data),
        },
        timeout: 15_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          try {
            const json = JSON.parse(Buffer.concat(chunks).toString("utf8")) as UnlockHttpResponse;
            resolve({ status: res.statusCode ?? 0, json });
          } catch {
            reject(new Error("remote unlock: malformed HTTP response"));
          }
        });
      },
    );
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("remote unlock: connection timed out"));
    });
    req.end(data);
  });
}

function isChallengeBody(
  json: UnlockHttpResponse,
): json is UnlockHttpResponse & { challenge: UnlockChallenge } {
  return json.status === "challenge" && json.challenge !== undefined;
}

export interface RemoteUnlockClientOpts extends RemoteHttpPeer {
  hubIdentity: SyncIdentity;
  unlockWrap: UnlockWrap;
  policy?: UnlockPolicy;
  now?: () => number;
  request?: RemoteHttpsJsonFn;
}

export type RemoteUnlockClientResult =
  | { ok: true; policy: UnlockPolicy }
  | { ok: false; reason: string };

/**
 * Complete a remote-unlock round-trip against a receiver listener.
 * Caller authenticates (Touch ID) before invoking — this function only does crypto + HTTP.
 */
export async function remoteUnlockViaHttp(
  opts: RemoteUnlockClientOpts,
): Promise<RemoteUnlockClientResult> {
  const post = opts.request ?? unlockHttpsJson;
  const now = opts.now ?? (() => Date.now());

  let challengeRes: { status: number; json: UnlockHttpResponse };
  try {
    challengeRes = await post({
      host: opts.host,
      port: opts.port,
      ca: opts.ca,
      path: UNLOCK_PATH,
      body: { op: "challenge" },
    });
  } catch {
    return { ok: false, reason: "unreachable" };
  }

  if (!isChallengeBody(challengeRes.json)) {
    return {
      ok: false,
      reason: challengeRes.json.reason ?? `challenge-failed:${challengeRes.status}`,
    };
  }

  const challenge = parseUnlockWireMessage(challengeRes.json.challenge);
  if (challenge.op !== "challenge") {
    return { ok: false, reason: "bad-request" };
  }

  let response: UnlockResponse;
  try {
    response = buildUnlockResponse({
      hubIdentity: opts.hubIdentity,
      unlockWrap: opts.unlockWrap,
      challenge,
      policy: opts.policy,
      now: now(),
    });
  } catch (err) {
    const reason =
      err && typeof err === "object" && "reason" in err
        ? String((err as { reason: string }).reason)
        : "build-failed";
    return { ok: false, reason };
  }

  let unlockRes: { status: number; json: UnlockHttpResponse };
  try {
    unlockRes = await post({
      host: opts.host,
      port: opts.port,
      ca: opts.ca,
      path: UNLOCK_PATH,
      body: response,
    });
  } catch {
    return { ok: false, reason: "unreachable" };
  }

  if (unlockRes.json.status === "unlocked") {
    return {
      ok: true,
      policy: unlockRes.json.policy ?? response.policy,
    };
  }
  return {
    ok: false,
    reason: unlockRes.json.reason ?? `unlock-failed:${unlockRes.status}`,
  };
}

/** In-process round-trip (no HTTP) — for tests and loopback harnesses. */
export async function remoteUnlockLoopback(opts: {
  session: {
    issueChallenge: () => { response: UnlockHttpResponse };
    acceptResponse: (raw: unknown) => Promise<{ response: UnlockHttpResponse; reason?: string }>;
  };
  hubIdentity: SyncIdentity;
  unlockWrap: UnlockWrap;
  policy?: UnlockPolicy;
  now?: () => number;
}): Promise<RemoteUnlockClientResult> {
  const now = opts.now ?? (() => Date.now());
  const issued = opts.session.issueChallenge();
  if (!isChallengeBody(issued.response)) {
    return { ok: false, reason: issued.response.reason ?? "challenge-failed" };
  }
  const challenge = parseUnlockWireMessage(issued.response.challenge);
  if (challenge.op !== "challenge") return { ok: false, reason: "bad-request" };

  let response: UnlockResponse;
  try {
    response = buildUnlockResponse({
      hubIdentity: opts.hubIdentity,
      unlockWrap: opts.unlockWrap,
      challenge,
      policy: opts.policy,
      now: now(),
    });
  } catch (err) {
    const reason =
      err && typeof err === "object" && "reason" in err
        ? String((err as { reason: string }).reason)
        : "build-failed";
    return { ok: false, reason };
  }

  const out = await opts.session.acceptResponse(response);
  if (out.response.status === "unlocked") {
    return {
      ok: true,
      policy: out.response.policy ?? response.policy,
    };
  }
  return { ok: false, reason: out.response.reason ?? out.reason ?? "unlock-failed" };
}

export type RemoteLockClientResult = { ok: true } | { ok: false; reason: string };

export async function remoteLockViaHttp(opts: {
  host: string;
  port: number;
  ca: string;
  hubIdentity: SyncIdentity;
  peerDeviceId: string;
  now?: () => number;
  request?: RemoteHttpsJsonFn;
}): Promise<RemoteLockClientResult> {
  const post = opts.request ?? unlockHttpsJson;
  const now = opts.now ?? (() => Date.now());
  let body;
  try {
    body = buildLockRequest({
      hubIdentity: opts.hubIdentity,
      peerDeviceId: opts.peerDeviceId,
      now: now(),
    });
  } catch (err) {
    const reason =
      err && typeof err === "object" && "reason" in err
        ? String((err as { reason: string }).reason)
        : "build-failed";
    return { ok: false, reason };
  }

  let res: { status: number; json: UnlockHttpResponse };
  try {
    res = await post({
      host: opts.host,
      port: opts.port,
      ca: opts.ca,
      path: LOCK_PATH,
      body,
    });
  } catch {
    return { ok: false, reason: "unreachable" };
  }
  if (res.json.status === "locked") return { ok: true };
  return { ok: false, reason: res.json.reason ?? `lock-failed:${res.status}` };
}

export type RemoteStatusClientResult =
  | { ok: true; enrolled: boolean; locked: boolean; deviceId?: string }
  | { ok: false; reason: string };

export async function remoteStatusViaHttp(opts: {
  host: string;
  port: number;
  ca: string;
  request?: RemoteHttpsJsonFn;
}): Promise<RemoteStatusClientResult> {
  const post = opts.request ?? unlockHttpsJson;
  let res: { status: number; json: UnlockHttpResponse };
  try {
    res = await post({
      host: opts.host,
      port: opts.port,
      ca: opts.ca,
      path: STATUS_PATH,
      body: {},
    });
  } catch {
    return { ok: false, reason: "unreachable" };
  }
  if (res.json.status !== "ok") {
    return { ok: false, reason: res.json.reason ?? `status-failed:${res.status}` };
  }
  return {
    ok: true,
    enrolled: Boolean(res.json.enrolled),
    locked: Boolean(res.json.locked),
    deviceId: typeof res.json.deviceId === "string" ? res.json.deviceId : undefined,
  };
}

export type RemoteEnrollFetchResult =
  | { ok: true; offer: EnrollOffer; listenerCert?: string }
  | { ok: false; reason: string };

/**
 * Fetch a sealed enroll offer from an unlocked receiver (PR 2 over PR 3 transport).
 * First enroll may omit `ca` (TLS TOFU); authenticity is the enroll offer Ed25519
 * against the paired peer key. Later unlocks use unlockWrap.listenerCert as CA.
 */
export async function remoteEnrollViaHttp(opts: {
  host: string;
  port: number;
  ca?: string;
  /** How the receiver names this hub (source peer name/id). */
  hubNameOrId: string;
  request?: RemoteHttpsJsonFn;
}): Promise<RemoteEnrollFetchResult> {
  const post = opts.request ?? unlockHttpsJson;
  let res: { status: number; json: UnlockHttpResponse };
  try {
    res = await post({
      host: opts.host,
      port: opts.port,
      ca: opts.ca,
      path: ENROLL_PATH,
      body: { op: "offer", hub: opts.hubNameOrId },
    });
  } catch {
    return { ok: false, reason: "unreachable" };
  }
  if (res.json.status !== "offer" || !res.json.offer) {
    return { ok: false, reason: res.json.reason ?? `enroll-failed:${res.status}` };
  }
  return {
    ok: true,
    offer: res.json.offer,
    listenerCert: typeof res.json.listenerCert === "string" ? res.json.listenerCert : undefined,
  };
}
