import fs from "node:fs";
import crypto from "node:crypto";
import { deviceIdFile, ensureDir } from "./paths.js";

/** Non-secret local device id (UUID), created lazily at `~/.abracadabra/device-id` (0600). */
export function getOrCreateDeviceId(): string {
  ensureDir();
  const file = deviceIdFile();
  try {
    const existing = fs.readFileSync(file, "utf8").trim();
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(existing)) {
      return existing;
    }
  } catch {
    /* create below */
  }
  const id = crypto.randomUUID();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, id, { mode: 0o600 });
  fs.renameSync(tmp, file);
  return id;
}
