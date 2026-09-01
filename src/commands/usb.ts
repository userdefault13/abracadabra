import fs from "node:fs";
import path from "node:path";
import { Command } from "commander";
import {
  loadVault,
  saveVault,
  encryptVault,
  decryptEnvelope,
  writeEncryptedFile,
} from "../core/vault.js";
import type { Vault, VarEntry, Connection } from "../core/vault.js";
import { getMasterKey, restoreMasterKey, authenticate } from "../platform/index.js";
import { prompt, promptHidden } from "../core/prompt.js";
import { sealBundle, openBundle, readBundleFile } from "../core/backup.js";
import type { BackupBundle, BundlePayload } from "../core/backup.js";
import { syncStateFile, ensureDir } from "../core/paths.js";

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const yellow = (s: string) => `\x1b[33m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;

function fail(err: unknown): never {
  console.error(red(`✗ ${err instanceof Error ? err.message : String(err)}`));
  process.exit(1);
}

// ── volume discovery ────────────────────────────────────────────────────────

const BUNDLE_DIR = "abracadabra";

function mountedVolumes(): string[] {
  const root = "/Volumes";
  if (!fs.existsSync(root)) return [];
  return fs
    .readdirSync(root)
    .filter((name) => !name.startsWith("."))
    // exclude the boot/system volume ("System" + "Library" only exist there)
    .filter((name) => {
      const p = path.join(root, name);
      try {
        return !(fs.existsSync(path.join(p, "System")) && fs.existsSync(path.join(p, "Library")));
      } catch {
        return false;
      }
    })
    .map((name) => path.join(root, name));
}

function bundleDirFor(volOrDir: string): string {
  return volOrDir.endsWith(BUNDLE_DIR) ? volOrDir : path.join(volOrDir, BUNDLE_DIR);
}

function hasBundle(dir: string): boolean {
  return readLatestPointer(bundleDirFor(dir)) !== null;
}

function readLatestPointer(dir: string): string | null {
  try {
    const pointer = JSON.parse(
      fs.readFileSync(path.join(dir, "latest.json"), "utf8"),
    ) as { file?: string };
    if (!pointer.file) return null;
    const p = path.join(dir, pointer.file);
    return fs.existsSync(p) ? pointer.file : null;
  } catch {
    return null;
  }
}

/** Locate the latest bundle; throws when an explicit target is unusable, null when nothing found. */
export function resolveLatest(target?: string): string | null {
  const tryDir = (dir: string): string | null => {
    const f = readLatestPointer(dir);
    return f ? path.join(dir, f) : null;
  };
  if (target) {
    let asIs = target;
    if (!path.isAbsolute(asIs)) {
      asIs = fs.existsSync(path.join(process.cwd(), target))
        ? path.join(process.cwd(), target)
        : path.join("/Volumes", target);
    }
    let stat;
    try {
      stat = fs.statSync(asIs);
    } catch {
      throw new Error(`No such file or directory: ${target}`);
    }
    if (stat.isFile()) return asIs;
    const found = tryDir(bundleDirFor(asIs));
    if (!found) throw new Error(`No ${BUNDLE_DIR}/latest.json found in ${asIs}`);
    return found;
  }
  for (const vol of mountedVolumes()) {
    const found = tryDir(bundleDirFor(vol));
    if (found) return found;
  }
  return null;
}

async function pickVolume(promptLabel = "Which volume?"): Promise<string> {
  const vols = mountedVolumes();
  if (vols.length === 0) fail("No mounted volumes found under /Volumes");
  if (vols.length === 1) return vols[0];
  console.log(dim(promptLabel));
  vols.forEach((v, i) => {
    const marker = hasBundle(v) ? dim(" (abra backup)") : "";
    console.log(`  [${i + 1}] ${path.basename(v)}${marker}`);
  });
  const answer = await prompt(`Volume [1-${vols.length}]: `);
  const idx = Number(answer.trim());
  if (!Number.isInteger(idx) || idx < 1 || idx > vols.length) fail("Invalid choice");
  return vols[idx - 1];
}

function writeBundleToDir(
  dir: string,
  vaultEnc: { iv: string; tag: string; data: string },
  masterKey: Buffer,
  passphrase: string,
): string {
  const bundle = sealBundle(vaultEnc, masterKey, passphrase);
  fs.mkdirSync(dir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const file = path.join(dir, `backup-${stamp}.abrabak`);
  fs.writeFileSync(file, JSON.stringify(bundle, null, 2), { mode: 0o600 });
  // atomically repoint latest.json
  const pointerTmp = path.join(dir, "latest.json.tmp");
  fs.writeFileSync(pointerTmp, JSON.stringify({ file: path.basename(file), createdAt: Date.now() }));
  fs.renameSync(pointerTmp, path.join(dir, "latest.json"));
  return file;
}

// ── sync-state (base snapshot for 3-way merges) ─────────────────────────────

interface SyncState {
  lastSyncAt: number;
  base: Vault;
}

function loadSyncState(): SyncState | null {
  try {
    const raw = JSON.parse(fs.readFileSync(syncStateFile(), "utf8")) as SyncState;
    return raw && typeof raw === "object" && raw.base ? raw : null;
  } catch {
    return null;
  }
}

function saveSyncState(vault: Vault): void {
  ensureDir();
  const state: SyncState = { lastSyncAt: Date.now(), base: vault };
  const file = syncStateFile();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

// ── 3-way merge ─────────────────────────────────────────────────────────────

interface Conflict {
  scope: string; // project name or "connections/<provider>"
  key: string;
  ours?: VarEntry;
  theirs?: VarEntry;
}

/** Manual resolutions collected from prompts/flags, keyed "<scope>/<key>". */
type Resolutions = Map<string, VarEntry | undefined>; // undefined = delete

type VarMap = Record<string, VarEntry>;

function entryEq(a: VarEntry | undefined, b: VarEntry | undefined): boolean {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

function mergeVarMaps(
  scope: string,
  ours: VarMap,
  theirs: VarMap,
  base: VarMap,
  conflicts: Conflict[],
  resolutions: Resolutions,
): VarMap {
  const merged: VarMap = {};
  const keys = new Set([...Object.keys(ours), ...Object.keys(theirs)]);
  for (const key of keys) {
    const o = ours[key];
    const t = theirs[key];
    const b = base[key];
    if (entryEq(o, t)) {
      if (o) merged[key] = o; // identical on both sides
      continue;
    }
    const manual = resolutions.get(`${scope}/${key}`);
    if (manual !== undefined || resolutions.has(`${scope}/${key}`)) {
      if (manual) merged[key] = manual;
      continue;
    }
    const oursChanged = !entryEq(o, b);
    const theirsChanged = !entryEq(t, b);
    if (!theirsChanged) {
      if (o) merged[key] = o; // only we touched it (incl. delete)
    } else if (!oursChanged) {
      if (t) merged[key] = t; // only they touched it (incl. delete)
    } else if (o && t) {
      // edited on both sides → newest updatedAt wins; exact tie → conflict
      if (o.updatedAt >= t.updatedAt) merged[key] = o;
      else merged[key] = t;
      if (o.updatedAt === t.updatedAt) conflicts.push({ scope, key, ours: o, theirs: t });
    } else {
      // edited on one side, deleted on the other — recoverable but flag it
      conflicts.push({ scope, key, ours: o, theirs: t });
    }
  }
  return merged;
}

function mergeProjects(
  ours: Vault,
  theirs: Vault,
  base: Vault | null,
  conflicts: Conflict[],
  resolutions: Resolutions,
): { projects: Vault["projects"]; report: string[] } {
  const report: string[] = [];
  const mergedProjects: Vault["projects"] = {};
  const bProjects = base?.projects ?? {};
  const scopes = new Set([...Object.keys(ours.projects), ...Object.keys(theirs.projects)]);

  for (const name of [...scopes].sort()) {
    const o = ours.projects[name];
    const t = theirs.projects[name];
    const b = bProjects[name];
    if (!o || !t) {
      const winner = o ?? t!;
      const existedInBase = Boolean(b);
      if (!existedInBase) {
        mergedProjects[name] = winner;
        report.push(o ? `+ project ${bold(name)} pushed to USB` : `+ project ${bold(name)} pulled from USB`);
      } else {
        report.push(`− project ${bold(name)} was deleted on ${o ? "USB (removing here)" : "this machine (removing from USB)"}`);
      }
      continue;
    }
    const vars = mergeVarMaps(name, o.vars, t.vars, b?.vars ?? {}, conflicts, resolutions);
    mergedProjects[name] = { createdAt: o.createdAt, vars };
    if (JSON.stringify(vars) !== JSON.stringify(o.vars)) {
      const diff = Object.keys(vars).length - Object.keys(o.vars).length;
      report.push(
        diff === 0
          ? `~ vars updated in ${bold(name)}`
          : diff > 0
            ? `+ ${diff} var(s) added to ${bold(name)}`
            : `− ${-diff} var(s) removed from ${bold(name)}`,
      );
    }
  }
  return { projects: mergedProjects, report };
}

function mergeConnections(
  ours: Vault,
  theirs: Vault,
  base: Vault | null,
  conflicts: Conflict[],
  resolutions: Resolutions,
): { connections: NonNullable<Vault["connections"]>; report: string[] } {
  const report: string[] = [];
  const merged: NonNullable<Vault["connections"]> = {};
  const connScopes = new Set([
    ...Object.keys(ours.connections ?? {}),
    ...Object.keys(theirs.connections ?? {}),
  ]);
  const bConns = base?.connections ?? {};
  for (const provider of [...connScopes].sort()) {
    const o: Connection | undefined = ours.connections?.[provider];
    const t: Connection | undefined = theirs.connections?.[provider];
    const b = bConns[provider];
    if (o && t) {
      const vars = mergeVarMaps(`connections/${provider}`, o.vars, t.vars, b?.vars ?? {}, conflicts, resolutions);
      merged[provider] = { ...o, meta: { ...t.meta, ...o.meta }, vars };
    } else {
      merged[provider] = (o ?? t)!;
      report.push(`~ connection ${bold(provider)} synced`);
    }
  }
  return { connections: merged, report };
}

export function threeWayMerge(
  ours: Vault,
  theirs: Vault,
  base: Vault | null,
  resolutions: Resolutions,
): { merged: Vault; conflicts: Conflict[]; report: string[] } {
  const conflicts: Conflict[] = [];
  const projects = mergeProjects(ours, theirs, base, conflicts, resolutions);
  const conns = mergeConnections(ours, theirs, base, conflicts, resolutions);

  // passkeys + apiKeys: object-level rule — whichever side differs from base wins
  const oP = JSON.stringify(ours.passkeys ?? []);
  const tP = JSON.stringify(theirs.passkeys ?? []);
  const bP = JSON.stringify(base?.passkeys ?? []);
  const passkeys = oP !== bP ? ours.passkeys : theirs.passkeys;
  const oK = JSON.stringify(ours.apiKeys ?? {});
  const tK = JSON.stringify(theirs.apiKeys ?? {});
  const bK = JSON.stringify(base?.apiKeys ?? {});
  const apiKeys = oK !== bK ? ours.apiKeys : theirs.apiKeys;

  return {
    merged: {
      version: 1,
      projects: projects.projects,
      connections: conns.connections,
      passkeys,
      apiKeys,
    },
    conflicts,
    report: [...projects.report, ...conns.report],
  };
}

async function collectResolutions(conflicts: Conflict[], mode?: "theirs" | "ours"): Promise<Resolutions> {
  const resolutions: Resolutions = new Map();
  for (const c of conflicts) {
    let choice: "ours" | "theirs" = mode ?? "ours";
    if (!mode) {
      const fmt = (e: VarEntry | undefined) =>
        e === undefined
          ? dim("(deleted)")
          : `${JSON.stringify(e.value)} ${dim(`(${e.secret ? "secret" : "plain"} · edited ${new Date(e.updatedAt).toLocaleString()})`)}`;
      const newest =
        c.ours && c.theirs
          ? c.ours.updatedAt >= c.theirs.updatedAt
            ? "ours"
            : "theirs"
          : c.theirs === undefined
            ? "ours"
            : "theirs";
      console.log(`\n${yellow("⚠ conflict")} ${bold(c.scope)}/${c.key}`);
      console.log(`  ours  ${newest === "ours" ? green("(newest)") : "       "} : ${fmt(c.ours)}`);
      console.log(`  theirs ${newest === "theirs" ? green("(newest)") : "        "} : ${fmt(c.theirs)}`);
      const answer = await prompt("  Use [o]urs / [t]heirs / [Enter]=ours: ");      const a = answer.trim().toLowerCase();
      choice = a.startsWith("t") ? "theirs" : "ours";
    }
    const picked = choice === "theirs" ? c.theirs : c.ours;
    resolutions.set(`${c.scope}/${c.key}`, picked); // undefined ⇒ deletion
  }
  return resolutions;
}

// ── passphrase plumbing ─────────────────────────────────────────────────────

let activePassphrase: string | null = null;

async function openWithPrompts(bundle: BackupBundle): Promise<BundlePayload> {
  for (let attempt = 1; attempt <= 3; attempt++) {
    const pass = await promptHidden(
      `Backup passphrase (hidden)${attempt > 1 ? `, attempt ${attempt}/3` : ""}: `,
    );
    try {
      const payload = openBundle(bundle, pass);
      activePassphrase = pass;
      return payload;
    } catch {
      if (attempt === 3) fail("Wrong passphrase (3 attempts)");
      console.error(red("✗ Wrong passphrase"));
    }
  }
  throw new Error("unreachable");
}

async function cachedPassphrase(): Promise<string> {
  if (!activePassphrase) fail("Internal error: no passphrase cached");
  return activePassphrase;
}

// ── library-level API (shared with the web dash) ────────────────────────────

export class UsbNoBackupError extends Error {}
export class UsbConflictError extends Error {
  constructor(public conflicts: ConflictInfo[]) {
    super("sync conflicts need resolution");
  }
}
export class UsbWrongPassphraseError extends Error {}

export interface VolumeInfo {
  name: string;
  mount: string;
  backupFile?: string;
  backupAt?: number;
}

export interface ConflictInfo {
  scope: string;
  key: string;
  newest: "ours" | "theirs";
  ours?: string; // masked
  theirs?: string; // masked
}

export interface SyncPreview {
  report: string[];
  conflicts: ConflictInfo[];
  needsResolution: boolean;
}

function maskValue(v: string): string {
  if (v.length <= 4) return "••••";
  return `${v.slice(0, 2)}${"•".repeat(6)}${v.slice(-2)}`;
}

function toConflictInfo(c: Conflict): ConflictInfo {
  const ours = c.ours === undefined ? "(deleted)" : maskValue(c.ours.value);
  const theirs = c.theirs === undefined ? "(deleted)" : maskValue(c.theirs.value);
  const newest: "ours" | "theirs" =
    c.ours && c.theirs
      ? c.ours.updatedAt >= c.theirs.updatedAt
        ? "ours"
        : "theirs"
      : c.theirs === undefined
        ? "ours"
        : "theirs";
  return { scope: c.scope, key: c.key, newest, ours, theirs };
}

export function listVolumes(): VolumeInfo[] {
  return mountedVolumes().map((mount) => {
    const dir = bundleDirFor(mount);
    const f = readLatestPointer(dir);
    return f
      ? {
          name: path.basename(mount),
          mount,
          backupFile: f,
          backupAt: fs.statSync(path.join(dir, f)).mtimeMs,
        }
      : { name: path.basename(mount), mount };
  });
}

/** Write a fresh backup bundle of the current vault (Touch ID gated). */
export async function createBackup(targetDirOrVolume: string, passphrase: string): Promise<string> {
  await authenticate("abracadabra: export encrypted USB backup");
  const vault = await loadVault();
  const masterKey = await getMasterKey();
  return writeBundleToDir(
    bundleDirFor(targetDirOrVolume),
    encryptVault(vault, masterKey),
    masterKey,
    passphrase,
  );
}

interface PreparedSync {
  latestFile: string;
  merged: Vault;
  report: string[];
  conflictInfos: ConflictInfo[];
  hasConflicts: boolean;
}

async function prepareSync(
  target: string | undefined,
  passphrase: string,
  force?: "ours" | "theirs",
): Promise<PreparedSync> {
  const localVault = await loadVault();
  const base = loadSyncState()?.base ?? null;
  let latestFile: string | null;
  try {
    latestFile = resolveLatest(target);
  } catch (err) {
    throw err instanceof Error ? err : new Error(String(err));
  }
  if (!latestFile) throw new UsbNoBackupError("No abra backup found on any mounted volume");

  let remoteVault: Vault;
  try {
    const payload = openBundle(readBundleFile(latestFile), passphrase);
    remoteVault = decryptEnvelope(payload.vaultEnc, Buffer.from(payload.masterKey, "base64"));
  } catch {
    throw new UsbWrongPassphraseError("Wrong passphrase for the backup bundle");
  }

  // pre-pass to collect conflicts when a forced resolution mode is set
  const resolutions: Resolutions = new Map();
  if (force) {
    const probe = threeWayMerge(localVault, remoteVault, base, new Map());
    for (const c of probe.conflicts) {
      resolutions.set(`${c.scope}/${c.key}`, force === "theirs" ? c.theirs : c.ours);
    }
  }
  const { merged, conflicts, report } = threeWayMerge(localVault, remoteVault, base, resolutions);
  return {
    latestFile,
    merged,
    report,
    conflictInfos: conflicts.map(toConflictInfo),
    hasConflicts: conflicts.length > 0,
  };
}

/** Dry-run merge against the USB copy — no writes. */
export async function previewSync(
  target: string | undefined,
  passphrase: string,
): Promise<SyncPreview> {
  const p = await prepareSync(target, passphrase);
  return { report: p.report, conflicts: p.conflictInfos, needsResolution: p.hasConflicts };
}

/**
 * Apply a sync: write the merged vault locally and refresh the USB bundle so
 * both machines converge. Throws UsbConflictError when unresolved conflicts
 * remain and no `force` mode was given.
 */
export async function applySync(
  target: string | undefined,
  passphrase: string,
  force?: "ours" | "theirs",
): Promise<{ changed: boolean; file?: string; report: string[] }> {
  const p = await prepareSync(target, passphrase, force);
  if (p.hasConflicts && !force) throw new UsbConflictError(p.conflictInfos);
  if (p.report.length === 0) {
    saveSyncState(await loadVault());
    return { changed: false, file: path.basename(p.latestFile), report: [] };
  }
  await authenticate("abracadabra: sync vault with USB backup");
  await saveVault(p.merged);
  const masterKey = await getMasterKey();
  const file = writeBundleToDir(
    path.dirname(p.latestFile),
    encryptVault(p.merged, masterKey),
    masterKey,
    passphrase,
  );
  saveSyncState(p.merged);
  console.log(`✓ dash/usb: synced — refreshed ${path.basename(file)}`);
  return { changed: true, file: path.basename(file), report: p.report };
}

// ── commands ────────────────────────────────────────────────────────────────

export function registerUsbCommands(program: Command): void {
  const usb = program
    .command("usb")
    .description("Back up the vault to a USB drive and sync between computers");

  usb
    .command("list")
    .description("List mounted volumes and whether they hold an abra backup")
    .action(() => {
      const vols = mountedVolumes();
      if (vols.length === 0) {
        console.log(dim("No mounted volumes found under /Volumes"));
        return;
      }
      for (const v of vols) {
        let note = "";
        const dir = bundleDirFor(v);
        const f = readLatestPointer(dir);
        if (f) {
          const mtime = fs.statSync(path.join(dir, f)).mtime;
          note = green(` (backup ${new Date(mtime).toLocaleString()})`);
        }
        console.log(`${bold(path.basename(v))}${note}`);
      }
    });

  usb
    .command("backup")
    .description("Write an encrypted backup bundle (vault + master key) to a USB drive")
    .option("-v, --volume <dir>", "target volume mount point (e.g. /Volumes/STICK)")
    .option("-f, --file <dir>", "target directory (overrides --volume)")
    .action(async (opts: { volume?: string; file?: string }) => {
      try {
        const dir = bundleDirFor(opts.file ?? opts.volume ?? (await pickVolume("Where should the backup go?")));

        await authenticate("abracadabra: export encrypted backup to USB");
        const vault = await loadVault();
        const masterKey = await getMasterKey();

        const pass1 = await promptHidden("Passphrase for the backup bundle (min 8 chars, hidden): ");
        if (pass1.length < 8) fail("Passphrase must be at least 8 characters");
        if ((await promptHidden("Repeat passphrase: ")) !== pass1) fail("Passphrases do not match");

        const file = writeBundleToDir(dir, encryptVault(vault, masterKey), masterKey, pass1);
        console.log(green(`✓ Backup written: ${file}`));
        console.log(dim(`  restore with: abra usb restore`));
      } catch (err) {
        fail(err);
      }
    });

  usb
    .command("restore [target]")
    .description("Restore vault + master key from a bundle (.abrabak file, directory, or volume name; omitted = auto-detect)")
    .action(async (target?: string) => {
      try {
        const latest = resolveLatest(target);
        if (!latest) fail("No abra backup found on any mounted volume");
        const payload = await openWithPrompts(readBundleFile(latest));

        const vault: Vault = decryptEnvelope(
          payload.vaultEnc,
          Buffer.from(payload.masterKey, "base64"),
        );
        const nVars = Object.values(vault.projects).reduce(
          (n, p) => n + Object.keys(p.vars).length,
          0,
        );
        console.log(
          `\nBackup from ${bold(payload.meta.hostname)} — ${new Date(payload.meta.createdAt).toLocaleString()}`,
        );
        console.log(`  ${Object.keys(vault.projects).length} project(s), ${nVars} var(s)`);

        const answer = await prompt(
          red("This OVERWRITES your local vault AND master key. Type 'yes' to continue: "),
        );
        if (answer.trim().toLowerCase() !== "yes") {
          console.log(dim("Aborted"));
          return;
        }
        await authenticate("abracadabra: restore vault from USB backup");
        const masterKeyBuf = Buffer.from(payload.masterKey, "base64");
        await restoreMasterKey(masterKeyBuf, activePassphrase ?? undefined);
        writeEncryptedFile(payload.vaultEnc);
        fs.rmSync(syncStateFile(), { force: true }); // stale base snapshot
        console.log(green("✓ Restored vault and master key"));
      } catch (err) {
        fail(err);
      }
    });

  usb
    .command("sync")
    .description("Two-way sync between this machine and the USB backup (3-way merge, interactive conflict prompts)")
    .option("-v, --volume <dir>", "volume mount point holding abracadabra/")
    .option("-f, --file <file>", "explicit .abrabak file to sync against")
    .option("--dry-run", "show what would change without writing anything", false)
    .option("--theirs", "auto-resolve all conflicts with the USB version", false)
    .option("--ours", "auto-resolve all conflicts with this machine's version", false)
    .action(async (opts: { volume?: string; file?: string; dryRun: boolean; theirs: boolean; ours: boolean }) => {
      try {
        const forceMode = opts.theirs ? ("theirs" as const) : opts.ours ? ("ours" as const) : undefined;
        const localVault = await loadVault();
        const state = loadSyncState();
        const base = state?.base ?? null;
        if (!base) {
          console.log(yellow("⚠ no previous sync snapshot — first sync can only pull/push whole projects"));
        }

        const latest = resolveLatest(opts.file ?? opts.volume);
        if (!latest) {
          console.log(yellow("No backup on USB yet."));
          if (opts.dryRun) {
            console.log(dim("(dry run — nothing written)"));
            return;
          }
          await authenticate("abracadabra: export encrypted backup to USB");
          const dir = bundleDirFor(opts.volume ?? (await pickVolume()));
          const pass = await promptHidden("Choose a passphrase for the backup bundle (hidden): ");
          if (pass.length < 8) fail("Passphrase must be at least 8 characters");
          const masterKey = await getMasterKey();
          const file = writeBundleToDir(dir, encryptVault(localVault, masterKey), masterKey, pass);
          saveSyncState(localVault);
          console.log(green(`✓ Initial backup written: ${file}`));
          return;
        }

        const payload = await openWithPrompts(readBundleFile(latest));
        const remoteVault = decryptEnvelope(payload.vaultEnc, Buffer.from(payload.masterKey, "base64"));

        // pass 1 — discover conflicts
        const first = threeWayMerge(localVault, remoteVault, base, new Map());
        // pass 2 — re-merge with manual resolutions applied
        const resolutions = await collectResolutions(first.conflicts, forceMode);
        const { merged, report } = threeWayMerge(localVault, remoteVault, base, resolutions);

        console.log(`\nSyncing against ${dim(path.basename(latest))}`);
        if (report.length === 0) {
          console.log(green("✓ Already in sync"));
          if (!opts.dryRun) saveSyncState(localVault);
          return;
        }
        for (const line of report) console.log(`  ${line}`);

        if (opts.dryRun) {
          console.log(dim("\n(dry run — nothing written)"));
          return;
        }

        await saveVault(merged);
        // refresh the USB bundle so both sides converge on the merge result
        await authenticate("abracadabra: update USB backup");
        const masterKey = await getMasterKey();
        const file = writeBundleToDir(
          path.dirname(latest),
          encryptVault(merged, masterKey),
          masterKey,
          await cachedPassphrase(),
        );
        saveSyncState(merged);
        console.log(green(`✓ Sync complete — USB refreshed (${path.basename(file)})`));
      } catch (err) {
        fail(err);
      }
    });
}
