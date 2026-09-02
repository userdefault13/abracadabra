import os from "node:os";
import path from "node:path";
import fs from "node:fs";

function resolveAbraDir(): string {
  return (
    (process.env.ABRA_DIR && process.env.ABRA_DIR.trim()) ||
    path.join(os.homedir(), ".abracadabra")
  );
}

export function abraDir(): string {
  return resolveAbraDir();
}

export function vaultFile(): string {
  return path.join(resolveAbraDir(), "vault.enc");
}

export function masterKeyFile(): string {
  return path.join(resolveAbraDir(), "master.key.enc");
}

/** Snapshot of the vault as-of-last-successful-sync — enables 3-way merges. */
export function syncStateFile(): string {
  return path.join(resolveAbraDir(), "sync-state.json");
}

/** PEM CA/cert written by `abra serve --lan` for clients to pin with curl --cacert. */
export function lanServeCertFile(): string {
  return path.join(resolveAbraDir(), "lan-serve.pem");
}

export function licenseFile(): string {
  return path.join(resolveAbraDir(), "license.json");
}

/** @deprecated use abraDir() */
export const ABRA_DIR = resolveAbraDir();

/** @deprecated use vaultFile() */
export const VAULT_FILE = vaultFile();

/** @deprecated use masterKeyFile() */
export const MASTER_KEY_FILE = masterKeyFile();

/** @deprecated use syncStateFile() */
export const SYNC_STATE_FILE = syncStateFile();

export function ensureDir(): void {
  fs.mkdirSync(resolveAbraDir(), { recursive: true, mode: 0o700 });
}
