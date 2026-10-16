import https from "node:https";
import type { SyncIdentity, UnlockWrap } from "../core/vault.js";
import {
  UNLOCK_PATH,
  buildUnlockResponse,
  parseUnlockWireMessage,
  type UnlockChallenge,
  type UnlockPolicy,
  type UnlockResponse,
} from "./wire.js";
import type { UnlockHttpResponse } from "./listener.js";

/**
 * Hub-side client for remote unlock (used by CLI in PR 4).
 * Two POSTs: request challenge, then send sealed W response.
 * Never logs or returns W / master-key material.
 */

export interface RemoteUnlockClientOpts {
  host: string;
  port: number;
  /** PEM of the receiver listener cert (transport only). */
  ca: string;
  hubIdentity: SyncIdentity;
  unlockWrap: UnlockWrap;
  policy?: UnlockPolicy;
  now?: () => number;
  /** Override HTTPS request (tests). */
  request?: typeof unlockHttpsJson;
}

export type RemoteUnlockClientResult =
  | { ok: true; policy: UnlockPolicy }
  | { ok: false; reason: string };

async function unlockHttpsJson(
  opts: {
    host: string;
    port: number;
    ca: string;
    body: unknown;
  },
): Promise<{ status: number; json: UnlockHttpResponse }> {
  const data = JSON.stringify(opts.body);
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: opts.host,
        port: opts.port,
        path: UNLOCK_PATH,
        method: "POST",
        ca: opts.ca,
        checkServerIdentity: () => undefined,
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

function isChallengeBody(json: UnlockHttpResponse): json is UnlockHttpResponse & { challenge: UnlockChallenge } {
  return json.status === "challenge" && json.challenge !== undefined;
}

/**
 * Complete a remote-unlock round-trip against a receiver listener.
 * Caller authenticates (Touch ID) before invoking — this function only does crypto + HTTP.
 */
export async function remoteUnlockViaHttp(opts: RemoteUnlockClientOpts): Promise<RemoteUnlockClientResult> {
  const post = opts.request ?? unlockHttpsJson;
  const now = opts.now ?? (() => Date.now());

  let challengeRes: { status: number; json: UnlockHttpResponse };
  try {
    challengeRes = await post({
      host: opts.host,
      port: opts.port,
      ca: opts.ca,
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
      body: response,
    });
  } catch {
    return { ok: false, reason: "unreachable" };
  }

  if (unlockRes.json.status === "unlocked") {
    return { ok: true, policy: response.policy };
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
    return { ok: true, policy: response.policy };
  }
  return { ok: false, reason: out.response.reason ?? out.reason ?? "unlock-failed" };
}
