import crypto from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { send } from "./http-utils.js";

const SESSION_COOKIE = "abra_session";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

// ── browser sessions (in-memory, cookie token) ───────────────────────
const sessions = new Map<string, number>(); // token -> expiresAt

function pruneSessions(): void {
  const now = Date.now();
  for (const [token, expiresAt] of sessions) {
    if (expiresAt <= now) sessions.delete(token);
  }
}

export function getSessionToken(req: IncomingMessage): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === SESSION_COOKIE) return rest.join("=");
  }
  return undefined;
}

export function isAuthed(req: IncomingMessage): boolean {
  pruneSessions();
  const token = getSessionToken(req);
  if (!token) return false;
  return (sessions.get(token) ?? 0) > Date.now();
}

export function issueSession(res: ServerResponse): void {
  pruneSessions();
  const token = crypto.randomBytes(32).toString("base64url");
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  );
}

/** DELETE /api/session */
export function logout(res: ServerResponse): void {
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
  send(res, 200, { ok: true });
}
