import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import os from "node:os";
import { abraDir } from "../core/paths.js";
import { loadVault, encryptVault } from "../core/vault.js";
import { getMasterKey } from "../platform/index.js";
import { sealBundle } from "../core/backup.js";
import type { BackupBundle } from "../core/backup.js";
import { assertCloudPassphrase, CLOUD_SCRYPT } from "../core/passphrase.js";
import { licenseEnforcementEnabled } from "../license/config.js";
import { readActivation } from "../license/store.js";

const require = createRequire(import.meta.url);
const pkg = require("../../package.json") as { version: string };

export interface AbraCheckpointStateV1 {
  schemaVersion: 1;
  abraVersion: string;
  license: {
    wallet: string;
    activatedAt: string | null;
    enforcement: boolean;
  };
  vault: {
    projectCount: number;
    projects: Array<{ name: string; varCount: number; updatedAt: number }>;
  };
  machine: {
    machineId: string;
    platform: string;
  };
  checkpointedAt: string;
}

/** v2 may carry a passphrase-sealed BackupBundle (full vault portability). */
export interface AbraCheckpointStateV2 extends Omit<AbraCheckpointStateV1, "schemaVersion"> {
  schemaVersion: 2;
  /** Present when checkpoint was created with --full */
  sealedVault?: BackupBundle;
}

export type AbraCheckpointState = AbraCheckpointStateV1 | AbraCheckpointStateV2;

function machineIdPath(): string {
  return `${abraDir()}/machine-id`;
}

export function readMachineId(): string {
  const file = machineIdPath();
  try {
    const id = readFileSync(file, "utf8").trim();
    if (id) return id;
  } catch {
    /* create below */
  }
  mkdirSync(abraDir(), { recursive: true });
  const id = randomUUID();
  writeFileSync(file, `${id}\n`, { mode: 0o600 });
  return id;
}

async function buildMetadata(ownerWallet: string): Promise<Omit<AbraCheckpointStateV1, "schemaVersion">> {
  const vault = await loadVault();
  const activation = readActivation();
  const projects = Object.entries(vault.projects)
    .map(([name, p]) => ({
      name,
      varCount: Object.keys(p.vars).length,
      updatedAt: Math.max(0, ...Object.values(p.vars).map((v) => v.updatedAt || 0)),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));

  return {
    abraVersion: pkg.version,
    license: {
      wallet: ownerWallet.toLowerCase(),
      activatedAt: activation?.activatedAt ?? null,
      enforcement: licenseEnforcementEnabled(),
    },
    vault: {
      projectCount: projects.length,
      projects,
    },
    machine: {
      machineId: createHash("sha256").update(readMachineId()).digest("hex").slice(0, 32),
      platform: os.platform(),
    },
    checkpointedAt: new Date().toISOString(),
  };
}

/** Build checkpoint payload — metadata only by default; never plaintext secrets. */
export async function buildCheckpointState(ownerWallet: string): Promise<AbraCheckpointStateV1> {
  const meta = await buildMetadata(ownerWallet);
  return { schemaVersion: 1, ...meta };
}

/** Full checkpoint: metadata + passphrase-sealed BackupBundle (strong passphrase required). */
export async function buildFullCheckpointState(
  ownerWallet: string,
  passphrase: string,
): Promise<AbraCheckpointStateV2> {
  assertCloudPassphrase(passphrase);
  const meta = await buildMetadata(ownerWallet);
  const vault = await loadVault();
  const masterKey = await getMasterKey();
  const sealedVault = sealBundle(encryptVault(vault, masterKey), masterKey, passphrase, {
    kdf: CLOUD_SCRYPT,
  });
  return { schemaVersion: 2, ...meta, sealedVault };
}

export function extractSealedVault(state: unknown): BackupBundle | null {
  if (!state || typeof state !== "object") return null;
  const s = state as AbraCheckpointStateV2;
  if (s.schemaVersion !== 2 || !s.sealedVault) return null;
  if (s.sealedVault.format !== "abracadabra-backup") return null;
  return s.sealedVault;
}
