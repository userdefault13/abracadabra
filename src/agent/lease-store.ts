import fs from "node:fs";
import path from "node:path";
import { abraDir } from "../core/paths.js";
import type { GrantCaller } from "./grants.js";
import { loadDeviceKey, type DeviceKey } from "../remote/device-key.js";
import { isRemoteUnlockEnabled } from "../remote/feature.js";
import { getHubPin, type HubPin } from "../remote/hub-pin.js";
import {
  bindingEquals,
  leasePublicView,
  localLeaseMaxTtlSeconds,
  openSealedLease,
  parseLeaseRevokeRequest,
  parseSealedLease,
  verifyLeaseRevokeRequest,
  verifySealedLease,
  LeaseError,
  type SealedLease,
} from "../remote/lease.js";
import {
  assertPrivatePath,
  ensureRemoteDir,
  remoteDir,
  writePrivateFile,
} from "../remote/private-fs.js";

/**
 * Persisted bot leases for abra-agent. Survives vault lock (unlike GrantStore).
 * Files: `<abraDir>/remote/leases/<leaseId>.json` (0600) — sealed ciphertext only.
 */

export const LEASES_DIRNAME = "leases";

export interface LeaseCheckResult {
  granted: boolean;
  leaseId?: string;
  remainingMs?: number;
}

export interface LeaseRevealResult {
  leaseId: string;
  project: string;
  vars: Record<string, { value: string; secret: boolean; updatedAt: number }>;
  remainingMs: number;
}

export interface LeaseStoreDeps {
  base?: string;
  now?: () => number;
  loadDeviceKey?: (base: string) => DeviceKey;
  getHubPin?: (base: string) => HubPin | null;
  log?: (line: string) => void;
  /** Override feature flag (tests). */
  isEnabled?: () => boolean;
}

function safeLeaseFileName(leaseId: string): string {
  // UUID only — reject path tricks.
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(leaseId)) {
    throw new LeaseError("malformed", "invalid lease id");
  }
  return `${leaseId.toLowerCase()}.json`;
}

export function leasesDir(base: string = abraDir()): string {
  return path.join(remoteDir(base), LEASES_DIRNAME);
}

export function leaseFilePath(leaseId: string, base: string = abraDir()): string {
  return path.join(leasesDir(base), safeLeaseFileName(leaseId));
}

function ensureLeasesDir(base: string): void {
  ensureRemoteDir(base);
  const dir = leasesDir(base);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  assertPrivatePath(dir, { expectDir: true });
}

/**
 * On-disk lease store. Does not clear on agent lock.
 * Never logs secret values — only leaseId / project / result codes.
 */
export class LeaseStore {
  private readonly base: string;
  private readonly now: () => number;
  private readonly loadKey: (base: string) => DeviceKey;
  private readonly loadPin: (base: string) => HubPin | null;
  private readonly enabled: () => boolean;
  private readonly logFn?: (line: string) => void;

  constructor(deps: LeaseStoreDeps = {}) {
    this.base = deps.base ?? abraDir();
    this.now = deps.now ?? Date.now;
    this.loadKey = deps.loadDeviceKey ?? loadDeviceKey;
    this.loadPin = deps.getHubPin ?? getHubPin;
    this.enabled = deps.isEnabled ?? isRemoteUnlockEnabled;
    this.logFn = deps.log;
  }

  private log(op: string, detail: string): void {
    this.logFn?.(`lease ${op} ${detail}`);
  }

  /** List sealed lease files (metadata only after parse). */
  listIds(): string[] {
    const dir = leasesDir(this.base);
    if (!fs.existsSync(dir)) return [];
    try {
      assertPrivatePath(dir, { expectDir: true });
    } catch {
      return [];
    }
    return fs
      .readdirSync(dir)
      .filter((f) => f.endsWith(".json"))
      .map((f) => f.slice(0, -".json".length));
  }

  private readFile(leaseId: string): SealedLease | null {
    const file = leaseFilePath(leaseId, this.base);
    if (!fs.existsSync(file)) return null;
    try {
      assertPrivatePath(file, { expectDir: false });
      const text = fs.readFileSync(file, "utf8");
      return parseSealedLease(JSON.parse(text));
    } catch {
      return null;
    }
  }

  private writeLease(lease: SealedLease): void {
    ensureLeasesDir(this.base);
    const file = leaseFilePath(lease.leaseId, this.base);
    writePrivateFile(file, `${JSON.stringify(lease)}\n`);
  }

  delete(leaseId: string): boolean {
    const file = leaseFilePath(leaseId, this.base);
    if (!fs.existsSync(file)) return false;
    fs.rmSync(file, { force: true });
    return true;
  }

  /** Drop expired leases from disk. Returns count removed. */
  purgeExpired(now = this.now()): number {
    let n = 0;
    for (const id of this.listIds()) {
      const lease = this.readFile(id);
      if (!lease) {
        this.delete(id);
        n++;
        continue;
      }
      if (lease.expiresAt <= now) {
        this.delete(id);
        n++;
        this.log("purge", `leaseId=${id} result=expired`);
      }
    }
    return n;
  }

  /**
   * Ingest a hub-pushed lease: verify hub pin + peerId + expiry, replace any
   * older lease for the same project+binding. Requires ABRA_REMOTE_UNLOCK=1.
   */
  ingest(raw: unknown): { leaseId: string; project: string; replaced: number } {
    if (!this.enabled()) {
      throw new LeaseError("disabled", "remote unlock disabled");
    }
    const hubPin = this.loadPin(this.base);
    if (!hubPin) throw new LeaseError("not-enrolled", "hub pin missing");

    let device: DeviceKey;
    try {
      device = this.loadKey(this.base);
    } catch {
      throw new LeaseError("not-enrolled", "device key missing");
    }

    const lease = parseSealedLease(raw);
    const now = this.now();
    try {
      verifySealedLease(lease, hubPin, {
        now,
        expectedPeerId: device.id,
        maxTtlSeconds: localLeaseMaxTtlSeconds(),
      });
      // Decrypt once to ensure ciphertext is valid for this device (discard plaintext).
      openSealedLease(lease, device);
    } catch (err) {
      if (err instanceof LeaseError && err.reason === "expired") {
        this.delete(lease.leaseId);
      }
      this.log("ingest", `leaseId=${lease.leaseId} result=${err instanceof LeaseError ? err.reason : "failed"}`);
      throw err;
    }

    let replaced = 0;
    for (const id of this.listIds()) {
      if (id === lease.leaseId.toLowerCase()) continue;
      const existing = this.readFile(id);
      if (!existing) {
        this.delete(id);
        continue;
      }
      if (
        existing.project === lease.project &&
        bindingEquals(existing.binding, lease.binding)
      ) {
        this.delete(id);
        replaced++;
      }
    }

    this.writeLease(lease);
    this.log(
      "ingest",
      `leaseId=${lease.leaseId} project=${lease.project} result=ok replaced=${replaced}`,
    );
    return {
      leaseId: lease.leaseId,
      project: lease.project,
      replaced,
    };
  }

  /**
   * Find a non-expired lease matching project + GrantCaller binding.
   * Expired matches are deleted. Does not decrypt.
   */
  findMatching(project: string, caller: GrantCaller, now = this.now()): SealedLease | null {
    this.purgeExpired(now);
    const want = project.trim();
    for (const id of this.listIds()) {
      const lease = this.readFile(id);
      if (!lease) {
        this.delete(id);
        continue;
      }
      if (lease.expiresAt <= now) {
        this.delete(id);
        continue;
      }
      if (lease.project !== want) continue;
      if (!bindingEquals(lease.binding, caller)) continue;
      return lease;
    }
    return null;
  }

  check(project: string, caller: GrantCaller, now = this.now()): LeaseCheckResult {
    if (!this.enabled()) return { granted: false };
    const lease = this.findMatching(project, caller, now);
    if (!lease) return { granted: false };
    return {
      granted: true,
      leaseId: lease.leaseId,
      remainingMs: Math.max(0, lease.expiresAt - now),
    };
  }

  /**
   * Serve project secrets from a matching lease even while the vault is locked.
   * Wrong binary / other project / expired / tampered → refuse (expired purged).
   */
  reveal(project: string, caller: GrantCaller, now = this.now()): LeaseRevealResult {
    if (!this.enabled()) {
      throw new LeaseError("disabled", "remote unlock disabled");
    }
    const want = project.trim();
    if (!want) throw new LeaseError("malformed", "project is required");

    const lease = this.findMatching(want, caller, now);
    if (!lease) {
      // Distinguish wrong project vs wrong binding for clearer refusal (no secrets).
      const anyForProject = this.listIds().some((id) => {
        const l = this.readFile(id);
        return l && l.project === want && l.expiresAt > now;
      });
      if (anyForProject) {
        this.log("reveal", `project=${want} result=wrong-binding`);
        throw new LeaseError("wrong-binding", "no lease for this caller binding");
      }
      this.log("reveal", `project=${want} result=wrong-project`);
      throw new LeaseError("wrong-project", "no lease for this project");
    }

    const hubPin = this.loadPin(this.base);
    if (!hubPin) throw new LeaseError("not-enrolled", "hub pin missing");
    let device: DeviceKey;
    try {
      device = this.loadKey(this.base);
    } catch {
      throw new LeaseError("not-enrolled", "device key missing");
    }

    try {
      verifySealedLease(lease, hubPin, {
        now,
        expectedPeerId: device.id,
        maxTtlSeconds: localLeaseMaxTtlSeconds(),
      });
      const opened = openSealedLease(lease, device);
      this.log("reveal", `leaseId=${lease.leaseId} project=${want} result=ok`);
      return {
        leaseId: lease.leaseId,
        project: want,
        vars: opened.vars,
        remainingMs: Math.max(0, lease.expiresAt - now),
      };
    } catch (err) {
      if (err instanceof LeaseError && err.reason === "expired") {
        this.delete(lease.leaseId);
      }
      if (err instanceof LeaseError && err.reason === "bad-signature") {
        this.log("reveal", `leaseId=${lease.leaseId} result=tampered`);
      } else {
        this.log(
          "reveal",
          `leaseId=${lease.leaseId} result=${err instanceof LeaseError ? err.reason : "failed"}`,
        );
      }
      throw err;
    }
  }

  /** Metadata for tests / status — never includes ct or secrets. */
  listPublic(now = this.now()): ReturnType<typeof leasePublicView>[] {
    this.purgeExpired(now);
    const out: ReturnType<typeof leasePublicView>[] = [];
    for (const id of this.listIds()) {
      const lease = this.readFile(id);
      if (!lease) continue;
      out.push(leasePublicView(lease));
    }
    return out;
  }

  /**
   * Apply a verified hub revoke: delete one leaseId or all leases from that hub.
   * Requires ABRA_REMOTE_UNLOCK=1 + hub pin + device key.
   */
  applyRevoke(raw: unknown): { removed: number; leaseIds: string[] } {
    if (!this.enabled()) {
      throw new LeaseError("disabled", "remote unlock disabled");
    }
    const hubPin = this.loadPin(this.base);
    if (!hubPin) throw new LeaseError("not-enrolled", "hub pin missing");

    let device: DeviceKey;
    try {
      device = this.loadKey(this.base);
    } catch {
      throw new LeaseError("not-enrolled", "device key missing");
    }

    const parsed = parseLeaseRevokeRequest(raw);
    verifyLeaseRevokeRequest(parsed, hubPin, {
      now: this.now(),
      expectedPeerId: device.id,
    });

    const removedIds: string[] = [];
    if (parsed.all) {
      for (const id of this.listIds()) {
        const lease = this.readFile(id);
        if (!lease) {
          this.delete(id);
          continue;
        }
        if (lease.from !== parsed.from) continue;
        if (this.delete(id)) removedIds.push(id);
      }
    } else if (parsed.leaseId) {
      const lease = this.readFile(parsed.leaseId);
      if (lease) {
        if (lease.from !== parsed.from) {
          throw new LeaseError("wrong-hub", "lease revoke from mismatch");
        }
        if (this.delete(parsed.leaseId)) removedIds.push(parsed.leaseId);
      }
    }

    this.log(
      "revoke",
      `result=ok removed=${removedIds.length}` +
        (parsed.leaseId ? ` leaseId=${parsed.leaseId}` : " all=1"),
    );
    return { removed: removedIds.length, leaseIds: removedIds };
  }
}
