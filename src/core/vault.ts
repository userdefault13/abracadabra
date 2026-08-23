import fs from "node:fs";
import crypto from "node:crypto";
import { VAULT_FILE, ensureDir } from "./paths.js";
import { getMasterKey } from "./keychain.js";

export interface VarEntry {
  value: string;
  secret: boolean;
  updatedAt: number;
}

export interface Project {
  createdAt: number;
  vars: Record<string, VarEntry>;
}

export interface Connection {
  provider: string;
  label?: string;
  createdAt: number;
  /** Non-secret metadata (key name, org id, scopes…). */
  meta: Record<string, string>;
  /** Credentials, stored like vars (secret flag respected). */
  vars: Record<string, VarEntry>;
}

export interface Vault {
  version: 1;
  projects: Record<string, Project>;
  connections?: Record<string, Connection>;
}

interface EncryptedFile {
  format: "abracadabra-vault";
  version: 1;
  iv: string;
  tag: string;
  data: string;
}

export function emptyVault(): Vault {
  return { version: 1, projects: {}, connections: {} };
}

export function assertConnection(vault: Vault, provider: string): Connection {
  const conn = vault.connections?.[provider];
  if (!conn) throw new Error(`No connection for "${provider}". Run: abra connect ${provider}`);
  return conn;
}

function encrypt(vault: Vault, key: Buffer): EncryptedFile {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(vault), "utf8");
  const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    format: "abracadabra-vault",
    version: 1,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: data.toString("base64"),
  };
}

function decrypt(file: unknown, key: Buffer): Vault {
  const f = file as EncryptedFile;
  if (f.format !== "abracadabra-vault") throw new Error("Unrecognized vault file");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(f.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(f.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(f.data, "base64")),
    decipher.final(),
  ]);
  return JSON.parse(plaintext.toString("utf8")) as Vault;
}

export async function loadVault(): Promise<Vault> {
  const key = await getMasterKey();
  if (!fs.existsSync(VAULT_FILE)) return emptyVault();
  const raw = JSON.parse(fs.readFileSync(VAULT_FILE, "utf8"));
  const vault = decrypt(raw, key);
  vault.connections ??= {};
  return vault;
}

export async function saveVault(vault: Vault): Promise<void> {
  ensureDir();
  const key = await getMasterKey();
  const enc = encrypt(vault, key);
  const tmp = `${VAULT_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(enc, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, VAULT_FILE);
}

export function assertProject(vault: Vault, name: string): Project {
  const project = vault.projects[name];
  if (!project) throw new Error(`Project not found: ${name}`);
  return project;
}
