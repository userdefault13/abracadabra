import crypto from "node:crypto";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from "@simplewebauthn/server";
import { loadVault, saveVault } from "../core/vault.js";
import type { Vault, PasskeyCredential } from "../core/vault.js";
import { authenticate } from "../platform/index.js";
import { send } from "./http-utils.js";
import { issueSession } from "./session.js";

const RP_NAME = "abracadabra";
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

// pending WebAuthn challenges, keyed by rpID
const challenges = new Map<string, { value: string; expiresAt: number }>();

function setChallenge(rpId: string, value: string): void {
  const now = Date.now();
  for (const [key, entry] of challenges) {
    if (entry.expiresAt <= now) challenges.delete(key);
  }
  challenges.set(rpId, { value, expiresAt: now + CHALLENGE_TTL_MS });
}

function takeChallenge(rpId: string): string | undefined {
  const entry = challenges.get(rpId);
  if (!entry || entry.expiresAt <= Date.now()) return undefined;
  challenges.delete(rpId);
  return entry.value;
}

/** Derive the WebAuthn rpID/origin from the request's Origin (falls back to Host). */
function originOf(req: { headers: { origin?: string; host?: string } }): {
  origin: string;
  rpId: string;
} {
  const origin = req.headers.origin ?? `http://${req.headers.host ?? "127.0.0.1"}`;
  const rpId = new URL(origin).hostname;
  return { origin, rpId };
}

function myPasskeys(vault: Vault, rpId: string): PasskeyCredential[] {
  return (vault.passkeys ?? []).filter((p) => p.rpId === rpId);
}

/**
 * POST /api/passkey/register/options
 * Adding a passkey is Touch ID gated — only someone at this machine can enroll one.
 */
export async function registerOptions(
  req: { headers: { origin?: string; host?: string } },
  res: import("node:http").ServerResponse,
): Promise<void> {
  try {
    await authenticate("abracadabra: register a passkey for the web dash");
  } catch {
    send(res, 403, { error: "biometric authentication denied" });
    return;
  }
  const { rpId } = originOf(req);
  const vault = await loadVault();
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: rpId,
    userID: crypto.randomBytes(16),
    userName: "abracadabra-dash",
    attestationType: "none",
    excludeCredentials: myPasskeys(vault, rpId).map((p) => ({ id: p.id })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "required",
      authenticatorAttachment: "platform",
    },
  });
  setChallenge(rpId, options.challenge);
  send(res, 200, options);
}

/** POST /api/passkey/register/verify — body is the browser's RegistrationResponseJSON */
export async function registerVerify(
  req: { headers: { origin?: string; host?: string } },
  body: Record<string, unknown>,
  res: import("node:http").ServerResponse,
): Promise<void> {
  const { origin, rpId } = originOf(req);
  const expectedChallenge = takeChallenge(rpId);
  if (!expectedChallenge) {
    send(res, 400, { error: "no pending registration — request options first" });
    return;
  }
  try {
    const verification = await verifyRegistrationResponse({
      response: body as unknown as RegistrationResponseJSON,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpId,
      requireUserVerification: true,
    });
    if (!verification.verified || !verification.registrationInfo) {
      send(res, 401, { error: "passkey registration failed" });
      return;
    }
    const { credential } = verification.registrationInfo;
    const vault = await loadVault();
    vault.passkeys ??= [];
    vault.passkeys.push({
      id: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString("base64"),
      counter: credential.counter,
      rpId,
      createdAt: Date.now(),
    });
    await saveVault(vault);
    console.log(`✓ passkey registered for web dash (rp: ${rpId})`);
    issueSession(res);
    send(res, 200, { ok: true });
  } catch (err) {
    send(res, 400, { error: err instanceof Error ? err.message : "registration failed" });
  }
}

/** POST /api/passkey/auth/options */
export async function authOptions(
  req: { headers: { origin?: string; host?: string } },
  res: import("node:http").ServerResponse,
): Promise<void> {
  const { rpId } = originOf(req);
  const vault = await loadVault();
  const creds = myPasskeys(vault, rpId);
  if (creds.length === 0) {
    send(res, 404, { error: "no passkey registered yet" });
    return;
  }
  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: creds.map((p) => ({ id: p.id })),
    userVerification: "required",
  });
  setChallenge(rpId, options.challenge);
  send(res, 200, options);
}

/** POST /api/passkey/auth/verify — body is the browser's AuthenticationResponseJSON */
export async function authVerify(
  req: { headers: { origin?: string; host?: string } },
  body: Record<string, unknown>,
  res: import("node:http").ServerResponse,
): Promise<void> {
  const { origin, rpId } = originOf(req);
  const expectedChallenge = takeChallenge(rpId);
  if (!expectedChallenge) {
    send(res, 400, { error: "no pending authentication — request options first" });
    return;
  }
  const credId = typeof (body as { id?: unknown }).id === "string" ? (body as { id: string }).id : "";
  const vault = await loadVault();
  const cred = (vault.passkeys ?? []).find((p) => p.id === credId);
  if (!cred) {
    send(res, 401, { error: "unknown passkey" });
    return;
  }
  try {
    const verification = await verifyAuthenticationResponse({
      response: body as unknown as AuthenticationResponseJSON,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: cred.rpId,
      requireUserVerification: true,
      credential: {
        id: cred.id,
        publicKey: new Uint8Array(Buffer.from(cred.publicKey, "base64")),
        counter: cred.counter,
      },
    });
    if (!verification.verified) {
      send(res, 401, { error: "passkey verification failed" });
      return;
    }
    cred.counter = verification.authenticationInfo.newCounter;
    await saveVault(vault);
    console.log("✓ web dash session opened (passkey)");
    issueSession(res);
    send(res, 200, { ok: true });
  } catch (err) {
    send(res, 401, { error: err instanceof Error ? err.message : "verification failed" });
  }
}
