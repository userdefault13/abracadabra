import fs from "node:fs";
import path from "node:path";
import { abraDir } from "../core/paths.js";
import { ensureRemoteDir, remoteDir } from "./private-fs.js";

/**
 * Append-only remote-unlock audit log (both hub and receiver).
 * JSON lines: { ts, op, peer?, result } — never secret values.
 */

export const AUDIT_LOG_FILENAME = "audit.log";

export interface AuditEntry {
  ts: number;
  op: string;
  peer?: string;
  result: string;
}

export function auditLogPath(base: string = abraDir()): string {
  return path.join(remoteDir(base), AUDIT_LOG_FILENAME);
}

/** Append one audit line. Failures are swallowed so audit never breaks unlock. */
export function appendAuditLog(
  entry: Omit<AuditEntry, "ts"> & { ts?: number },
  opts: { base?: string; now?: () => number } = {},
): void {
  const base = opts.base ?? abraDir();
  const line: AuditEntry = {
    ts: entry.ts ?? (opts.now ?? Date.now)(),
    op: String(entry.op),
    result: String(entry.result),
  };
  if (entry.peer !== undefined && entry.peer !== "") {
    line.peer = String(entry.peer);
  }
  // Refuse accidental secret-shaped fields — only allow the known keys.
  const text = `${JSON.stringify(line)}\n`;
  try {
    ensureRemoteDir(base);
    fs.appendFileSync(auditLogPath(base), text, { mode: 0o600 });
  } catch {
    /* never break local unlock / CLI on audit I/O */
  }
}
