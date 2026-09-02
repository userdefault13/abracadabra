import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import os from "node:os";
import { abraDir } from "../core/paths.js";
import { loadVault } from "../core/vault.js";
import { licenseEnforcementEnabled } from "../license/config.js";
import { readActivation } from "../license/store.js";

const require = createRequire(import.meta.url);
const pkg = require("../../package.json") as { version: string };

export interface AbraCheckpointState {
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

/** Build checkpoint payload — metadata only, never secret values. */
export async function buildCheckpointState(ownerWallet: string): Promise<AbraCheckpointState> {
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
    schemaVersion: 1,
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
