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
import type { Vault, VarEntry } from "../core/vault.js";
import { getMasterKey, restoreMasterKey, authenticate } from "../platform/index.js";
import { prompt, promptHidden } from "../core/prompt.js";
import {
  sealBundle,
  sealScopedBundle,
  openAnyBundle,
  readBundleFile,
} from "../core/backup.js";
import type { BackupBundle, ScopedBundlePayload } from "../core/backup.js";
import { syncStateFile } from "../core/paths.js";
import {
  threeWayMerge,
  loadSyncState,
  saveSyncState,
  type Resolutions,
  type Conflict,
} from "../core/sync.js";
import {
  assertScopeNamesAllowed,
  validateScope,
  extractScopedProjects,
  mergeScopedProjects,
  formatScopedReport,
} from "../core/sync-scope.js";
import { mountedVolumes, resolveVolumePath, volumesRootLabel } from "../core/volumes.js";
import {
  startLanHost,
  stopLanHost,
  getLanHostStatus,
  LAN_DEFAULT_PORT,
  LAN_DEFAULT_TTL_MS,
} from "../usb/lan-host.js";
import {
  browseLanPeers,
  previewLanSync,
  applyLanSync,
  scopedLanSync,
  fetchLanInfo,
  LanConflictError,
  parseHostPort,
} from "../usb/lan-client.js";

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const yellow = (s: string) => `\x1b[33m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;

function fail(err: unknown): never {
  console.error(red(`✗ ${err instanceof Error ? err.message : String(err)}`));
  process.exit(1);
}

const BUNDLE_DIR = "abracadabra";
const SCOPED_BUNDLE_MSG =
  "scoped bundle — merge it with `abra usb sync -f <file>`";

function collectProject(value: string, previous: string[]): string[] {
  return previous.concat([value]);
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
    if (!path.isAbsolute(asIs) && !/^[A-Za-z]:[\\/]/.test(asIs)) {
      asIs = fs.existsSync(path.join(process.cwd(), target))
        ? path.join(process.cwd(), target)
        : resolveVolumePath(target);
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
  if (vols.length === 0) fail(`No mounted volumes found under ${volumesRootLabel()}`);
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
  const pointerTmp = path.join(dir, "latest.json.tmp");
  fs.writeFileSync(pointerTmp, JSON.stringify({ file: path.basename(file), createdAt: Date.now() }));
  fs.renameSync(pointerTmp, path.join(dir, "latest.json"));
  return file;
}

function writeScopedBundleToDir(
  dir: string,
  projects: Record<string, import("../core/vault.js").Project>,
  scope: string[],
  passphrase: string,
): string {
  const bundle = sealScopedBundle(projects, scope, passphrase);
  fs.mkdirSync(dir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const file = path.join(dir, `scoped-${stamp}.abrabak`);
  fs.writeFileSync(file, JSON.stringify(bundle, null, 2), { mode: 0o600 });
  // Do NOT update latest.json — full sync/restore must never auto-pick a scoped bundle.
  return file;
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
      const answer = await prompt("  Use [o]urs / [t]heirs / [Enter]=ours: ");
      const a = answer.trim().toLowerCase();
      choice = a.startsWith("t") ? "theirs" : "ours";
    }
    const picked = choice === "theirs" ? c.theirs : c.ours;
    resolutions.set(`${c.scope}/${c.key}`, picked);
  }
  return resolutions;
}

let activePassphrase: string | null = null;

async function openAnyWithPrompts(
  bundle: BackupBundle,
): Promise<
  | { kind: "full"; payload: import("../core/backup.js").BundlePayload }
  | { kind: "scoped"; payload: ScopedBundlePayload }
> {
  for (let attempt = 1; attempt <= 3; attempt++) {
    const pass = await promptHidden(
      `Backup passphrase (hidden)${attempt > 1 ? `, attempt ${attempt}/3` : ""}: `,
    );
    try {
      const opened = openAnyBundle(bundle, pass);
      activePassphrase = pass;
      return opened;
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
  ours?: string;
  theirs?: string;
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
  const base = (await loadSyncState())?.base ?? null;
  let latestFile: string | null;
  try {
    latestFile = resolveLatest(target);
  } catch (err) {
    throw err instanceof Error ? err : new Error(String(err));
  }
  if (!latestFile) throw new UsbNoBackupError("No abra backup found on any mounted volume");

  let remoteVault: Vault;
  try {
    const opened = openAnyBundle(readBundleFile(latestFile), passphrase);
    if (opened.kind === "scoped") {
      throw new Error(SCOPED_BUNDLE_MSG);
    }
    remoteVault = decryptEnvelope(
      opened.payload.vaultEnc,
      Buffer.from(opened.payload.masterKey, "base64"),
    );
  } catch (err) {
    if (err instanceof Error && err.message === SCOPED_BUNDLE_MSG) throw err;
    throw new UsbWrongPassphraseError("Wrong passphrase for the backup bundle");
  }

  const resolutions: Resolutions = new Map();
  if (force) {
    const probe = threeWayMerge(localVault, remoteVault, base, new Map(), "USB");
    for (const c of probe.conflicts) {
      resolutions.set(`${c.scope}/${c.key}`, force === "theirs" ? c.theirs : c.ours);
    }
  }
  const { merged, conflicts, report } = threeWayMerge(
    localVault,
    remoteVault,
    base,
    resolutions,
    "USB",
  );
  return {
    latestFile,
    merged,
    report,
    conflictInfos: conflicts.map(toConflictInfo),
    hasConflicts: conflicts.length > 0,
  };
}

export async function previewSync(
  target: string | undefined,
  passphrase: string,
): Promise<SyncPreview> {
  const p = await prepareSync(target, passphrase);
  return { report: p.report, conflicts: p.conflictInfos, needsResolution: p.hasConflicts };
}

export async function applySync(
  target: string | undefined,
  passphrase: string,
  force?: "ours" | "theirs",
): Promise<{ changed: boolean; file?: string; report: string[] }> {
  const p = await prepareSync(target, passphrase, force);
  if (p.hasConflicts && !force) throw new UsbConflictError(p.conflictInfos);
  if (p.report.length === 0) {
    await saveSyncState(await loadVault());
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
  await saveSyncState(p.merged);
  console.log(`✓ dash/usb: synced — refreshed ${path.basename(file)}`);
  return { changed: true, file: path.basename(file), report: p.report };
}

/** Merge a scoped file bundle into the local vault (no sync-state, no rewrite of the file). */
async function applyScopedFileMerge(
  payload: ScopedBundlePayload,
  opts: { projects?: string[]; theirs?: boolean; dryRun?: boolean },
): Promise<{ changed: boolean; report: string[] }> {
  let incoming = payload.projects;
  let scope = payload.scope;
  if (opts.projects && opts.projects.length > 0) {
    const want = assertScopeNamesAllowed(opts.projects);
    const scopeSet = new Set(payload.scope);
    const outside = want.filter((n) => !scopeSet.has(n));
    if (outside.length > 0) {
      throw new Error(`requested project(s) outside bundle scope: ${outside.join(", ")}`);
    }
    scope = want;
    incoming = Object.fromEntries(
      want.map((n) => {
        const p = payload.projects[n];
        if (!p) throw new Error(`project "${n}" missing from scoped bundle`);
        return [n, p];
      }),
    );
  }
  assertScopeNamesAllowed(scope);
  assertScopeNamesAllowed(Object.keys(incoming));

  const local = await loadVault();
  const { merged, report, changed } = mergeScopedProjects(local, incoming, {
    theirs: opts.theirs === true,
  });
  const lines = formatScopedReport(report);

  if (opts.dryRun) return { changed, report: lines };
  if (!changed) return { changed: false, report: lines };

  await authenticate(
    `abracadabra: merge scoped project(s) ${scope.join(", ")} into this vault`,
  );
  await saveVault(merged);
  return { changed: true, report: lines };
}

/**
 * Write a scoped project backup under `<dir>/abracadabra/scoped-*.abrabak`.
 * Does not touch `latest.json`. Passphrase must be ≥ 8 characters.
 */
export async function createScopedBackup(
  dir: string,
  projects: string[],
  passphrase: string,
): Promise<string> {
  if (passphrase.length < 8) {
    throw new Error("Passphrase must be at least 8 characters");
  }
  const scope = assertScopeNamesAllowed(projects);
  await authenticate(
    `abracadabra: export scoped backup of project(s) ${scope.join(", ")}`,
  );
  const vault = await loadVault();
  const validated = validateScope(vault, scope);
  const extracted = extractScopedProjects(vault, validated);
  return writeScopedBundleToDir(bundleDirFor(dir), extracted, validated, passphrase);
}

/** Open a scoped `.abrabak` and merge it into the local vault (no sync-state). */
export async function mergeScopedBundleFile(
  file: string,
  passphrase: string,
  opts: { projects?: string[]; theirs?: boolean; dryRun?: boolean } = {},
): Promise<{ changed: boolean; report: string[] }> {
  const opened = openAnyBundle(readBundleFile(file), passphrase);
  if (opened.kind !== "scoped") {
    throw new Error("not a scoped bundle");
  }
  return applyScopedFileMerge(opened.payload, opts);
}

// Re-export LAN helpers for dash
export {
  startLanHost,
  stopLanHost,
  getLanHostStatus,
  browseLanPeers,
  previewLanSync,
  applyLanSync,
  scopedLanSync,
  fetchLanInfo,
  LanConflictError,
};

export function registerUsbCommands(program: Command): void {
  const usb = program
    .command("usb")
    .description("Back up / sync the vault via USB drive or local network");

  usb
    .command("list")
    .description("List mounted volumes (and optional LAN peers with --lan)")
    .option("--lan", "also browse mDNS for LAN sync hosts", false)
    .action(async (opts: { lan: boolean }) => {
      const vols = mountedVolumes();
      if (vols.length === 0) {
        console.log(dim(`No mounted volumes found under ${volumesRootLabel()}`));
      } else {
        for (const v of vols) {
          let note = "";
          const dir = bundleDirFor(v);
          const f = readLatestPointer(dir);
          if (f) {
            const mtime = fs.statSync(path.join(dir, f)).mtime;
            note = green(` (backup ${new Date(mtime).toLocaleString()})`);
          }
          // Label any scoped-*.abrabak files present
          try {
            const scoped = fs
              .readdirSync(dir)
              .filter((n) => n.startsWith("scoped-") && n.endsWith(".abrabak"));
            if (scoped.length > 0) {
              note += dim(` (${scoped.length} scoped bundle(s))`);
            }
          } catch {
            /* ignore */
          }
          console.log(`${bold(path.basename(v))}${note}`);
        }
      }
      if (opts.lan) {
        console.log(dim("\nLAN peers:"));
        const peers = await browseLanPeers();
        if (peers.length === 0) console.log(dim("  (none found)"));
        else {
          for (const p of peers) {
            console.log(
              `  ${bold(p.hostname || p.name)}  ${p.host}:${p.port}` +
                (p.fingerprint ? dim(`  fp ${p.fingerprint}`) : ""),
            );
          }
        }
      }
    });

  usb
    .command("peers")
    .description("Browse the LAN for abracadabra sync hosts (mDNS)")
    .action(async () => {
      const peers = await browseLanPeers();
      if (peers.length === 0) {
        console.log(dim("No LAN sync hosts found"));
        return;
      }
      for (const p of peers) {
        console.log(
          `${bold(p.hostname || p.name)}\t${p.host}:${p.port}` +
            (p.fingerprint ? `\t${dim(p.fingerprint)}` : ""),
        );
      }
    });

  usb
    .command("host")
    .description("Start a short-lived TLS LAN sync host (PIN + mDNS)")
    .option("--port <number>", "listen port", String(LAN_DEFAULT_PORT))
    .option("--ttl <seconds>", "session lifetime", String(LAN_DEFAULT_TTL_MS / 1000))
    .option("--no-advertise", "skip mDNS advertisement")
    .option(
      "-p, --project <name>",
      "share only this project (repeatable; scoped, read-only)",
      collectProject,
      [] as string[],
    )
    .action(
      async (opts: {
        port: string;
        ttl: string;
        advertise: boolean;
        project: string[];
      }) => {
        try {
          const projects = opts.project?.length ? opts.project : undefined;
          const handle = await startLanHost({
            port: Number(opts.port),
            ttlMs: Number(opts.ttl) * 1000,
            advertise: opts.advertise,
            projects,
          });
          console.log(green("✦ LAN sync host running"));
          console.log(`  PIN:          ${bold(handle.pin)}`);
          console.log(`  fingerprint:  ${handle.fingerprint}`);
          if (handle.scope?.length) {
            console.log(
              `  scope:        ${handle.scope.join(", ")} (read-only — no push-back, host vault untouched)`,
            );
          }
          console.log(`  expires:      ${new Date(handle.expiresAt).toLocaleString()}`);
          for (const addr of handle.addresses) {
            const fpFlag = ` --fingerprint ${handle.fingerprint}`;
            const projFlag = handle.scope?.length
              ? handle.scope.map((p) => ` --project ${p}`).join("")
              : "";
            console.log(
              `  connect:      abra usb sync --lan ${addr}:${handle.port}${fpFlag}${projFlag}`,
            );
          }
          if (handle.addresses.length === 0) {
            console.log(
              `  connect:      abra usb sync --lan <ip>:${handle.port} --fingerprint ${handle.fingerprint}`,
            );
          }
          console.log(dim("\nWaiting for a peer… Ctrl+C to stop"));
          const onSig = () => {
            void stopLanHost().then(() => process.exit(0));
          };
          process.on("SIGINT", onSig);
          process.on("SIGTERM", onSig);
          // stay alive until host stops (scoped hosts do not stop after pull)
          const tick = setInterval(() => {
            if (!getLanHostStatus()) {
              clearInterval(tick);
              console.log(dim("\nHost session ended"));
              process.exit(0);
            }
          }, 500);
        } catch (err) {
          fail(err);
        }
      },
    );

  usb
    .command("backup")
    .description("Write an encrypted backup bundle (vault + master key) to a USB drive")
    .option("-v, --volume <dir>", "target volume mount point")
    .option("-f, --file <dir>", "target directory (overrides --volume)")
    .option(
      "-p, --project <name>",
      "backup only this project (repeatable; scoped, merge-only)",
      collectProject,
      [] as string[],
    )
    .action(async (opts: { volume?: string; file?: string; project: string[] }) => {
      try {
        const target =
          opts.file ?? opts.volume ?? (await pickVolume("Where should the backup go?"));
        const dir = bundleDirFor(target);

        if (opts.project?.length) {
          assertScopeNamesAllowed(opts.project); // refuse reserved names before prompting
          const pass1 = await promptHidden(
            "Passphrase for the backup bundle (min 8 chars, hidden): ",
          );
          if (pass1.length < 8) fail("Passphrase must be at least 8 characters");
          if (pass1.length < 12) {
            console.log(
              yellow("⚠ passphrase is under 12 characters — 12+ recommended for scoped bundles"),
            );
          }
          if ((await promptHidden("Repeat passphrase: ")) !== pass1) fail("Passphrases do not match");

          const file = await createScopedBackup(target, opts.project, pass1);
          console.log(green(`✓ Scoped backup written: ${file}`));
          console.log(
            dim(`  merge with: abra usb sync -f ${file} [--project …] [--dry-run]`),
          );
          return;
        }

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
    .description(
      "Restore vault + master key from a bundle (.abrabak file, directory, or volume name; omitted = auto-detect)",
    )
    .action(async (target?: string) => {
      try {
        const latest = resolveLatest(target);
        if (!latest) fail("No abra backup found on any mounted volume");
        const opened = await openAnyWithPrompts(readBundleFile(latest));

        if (opened.kind === "scoped") {
          console.log(
            yellow(
              "This is a scoped bundle — merging into the local vault (conflicts keep this machine's values).",
            ),
          );
          console.log(
            `\nScoped backup from ${bold(opened.payload.meta.hostname)} — ${new Date(opened.payload.meta.createdAt).toLocaleString()}`,
          );
          console.log(`  scope: ${opened.payload.scope.join(", ")}`);
          const result = await mergeScopedBundleFile(latest, await cachedPassphrase(), {
            theirs: false,
          });
          for (const line of result.report) console.log(`  ${line}`);
          if (!result.changed) console.log(green("✓ already in sync (scoped)"));
          else console.log(green("✓ Scoped merge complete"));
          return;
        }

        const payload = opened.payload;
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
        fs.rmSync(syncStateFile(), { force: true });
        console.log(green("✓ Restored vault and master key"));
      } catch (err) {
        fail(err);
      }
    });

  usb
    .command("sync")
    .description("Two-way sync via USB backup or LAN peer (3-way merge); or one-way scoped merge with --project")
    .option("-v, --volume <dir>", "volume mount point holding abracadabra/")
    .option("-f, --file <file>", "explicit .abrabak file to sync against")
    .option("--lan [host]", "sync over LAN (host:port or mDNS name; omit to pick from peers)")
    .option("--pin <pin>", "LAN session PIN")
    .option("--fingerprint <fp>", "expected TLS fingerprint (required for LAN)")
    .option(
      "-p, --project <name>",
      "sync only this project (repeatable; scoped, one-way)",
      collectProject,
      [] as string[],
    )
    .option("--dry-run", "show what would change without writing anything", false)
    .option("--theirs", "auto-resolve all conflicts with the remote version", false)
    .option("--ours", "auto-resolve all conflicts with this machine's version (default for scoped)", false)
    .action(
      async (opts: {
        volume?: string;
        file?: string;
        lan?: string | boolean;
        pin?: string;
        fingerprint?: string;
        project: string[];
        dryRun: boolean;
        theirs: boolean;
        ours: boolean;
      }) => {
        try {
          const forceMode = opts.theirs ? ("theirs" as const) : opts.ours ? ("ours" as const) : undefined;
          const projects = opts.project?.length ? opts.project : undefined;

          if (opts.lan !== undefined && opts.lan !== false) {
            let target =
              typeof opts.lan === "string" && opts.lan.length > 0 ? opts.lan : "";
            if (!target) {
              const peers = await browseLanPeers();
              if (peers.length === 0) fail("No LAN sync hosts found — start one with: abra usb host");
              if (peers.length === 1) {
                target = `${peers[0].host}:${peers[0].port}`;
                if (!opts.fingerprint && peers[0].fingerprint) opts.fingerprint = peers[0].fingerprint;
              } else {
                console.log(dim("Pick a LAN host:"));
                peers.forEach((p, i) => {
                  console.log(`  [${i + 1}] ${p.hostname || p.name}  ${p.host}:${p.port}`);
                });
                const answer = await prompt(`Host [1-${peers.length}]: `);
                const idx = Number(answer.trim());
                if (!Number.isInteger(idx) || idx < 1 || idx > peers.length) fail("Invalid choice");
                const p = peers[idx - 1];
                target = `${p.host}:${p.port}`;
                if (!opts.fingerprint && p.fingerprint) opts.fingerprint = p.fingerprint;
              }
            } else if (!target.includes(":") && !/^\d+\.\d+\.\d+\.\d+$/.test(target)) {
              // treat as mDNS name substring
              const peers = await browseLanPeers();
              const match = peers.find(
                (p) =>
                  p.name.includes(target) ||
                  (p.hostname && p.hostname.includes(target)),
              );
              if (!match) fail(`No LAN peer matching "${target}"`);
              target = `${match.host}:${match.port}`;
              if (!opts.fingerprint && match.fingerprint) opts.fingerprint = match.fingerprint;
            } else {
              parseHostPort(target); // validate
            }

            if (!opts.fingerprint) {
              fail(
                "LAN sync requires the host's TLS fingerprint — pass --fingerprint <fp> exactly as printed by `abra usb host`",
              );
            }

            const pin =
              opts.pin?.trim() ||
              (await promptHidden("LAN PIN (hidden): ")).trim();
            if (!/^\d{6}$/.test(pin)) fail("PIN must be 6 digits");

            // Decide scoped vs unscoped
            let useScoped = Boolean(projects);
            if (!useScoped) {
              try {
                const info = await fetchLanInfo(target, opts.fingerprint);
                useScoped = Boolean(info.scoped);
              } catch {
                // If info fails, fall through to unscoped path (pull will surface errors).
              }
            }

            if (useScoped) {
              const result = await scopedLanSync(target, pin, {
                projects,
                theirs: opts.theirs === true,
                dryRun: opts.dryRun,
                expectedFingerprint: opts.fingerprint,
              });
              console.log(`\nScoped sync against LAN ${dim(target)}`);
              if (result.report.length === 0 && !result.changed) {
                console.log(green("✓ already in sync (scoped)"));
              } else {
                for (const line of result.report) console.log(`  ${line}`);
                if (!result.changed && !result.dryRun) {
                  console.log(green("✓ already in sync (scoped)"));
                } else if (!result.dryRun && result.changed) {
                  console.log(green("✓ Scoped LAN merge complete"));
                }
              }
              if (result.dryRun) console.log(dim("\n(dry run — nothing written)"));
              return;
            }

            if (opts.dryRun) {
              const preview = await previewLanSync(target, pin, opts.fingerprint);
              console.log(`\nSyncing against LAN ${dim(target)}`);
              if (preview.report.length === 0) console.log(green("✓ Already in sync"));
              else for (const line of preview.report) console.log(`  ${line}`);
              if (preview.needsResolution) {
                console.log(yellow(`⚠ ${preview.conflicts.length} conflict(s) — use --ours/--theirs`));
              }
              console.log(dim("\n(dry run — nothing written)"));
              return;
            }

            const result = await applyLanSync(target, pin, forceMode, opts.fingerprint);
            if (result.report.length === 0) console.log(green("✓ Already in sync"));
            else {
              for (const line of result.report) console.log(`  ${line}`);
              console.log(green(`✓ LAN sync complete${result.changed ? "" : " (no local changes)"}`));
            }
            return;
          }

          // ── File / volume sync ──────────────────────────────────────────
          const latest = resolveLatest(opts.file ?? opts.volume);

          if (latest) {
            const opened = await openAnyWithPrompts(readBundleFile(latest));
            if (opened.kind === "scoped") {
              console.log(`\nScoped sync against ${dim(path.basename(latest))}`);
              const result = await mergeScopedBundleFile(latest, await cachedPassphrase(), {
                projects,
                theirs: opts.theirs === true,
                dryRun: opts.dryRun,
              });
              if (result.report.length === 0 && !result.changed) {
                console.log(green("✓ already in sync (scoped)"));
              } else {
                for (const line of result.report) console.log(`  ${line}`);
                if (!result.changed) console.log(green("✓ already in sync (scoped)"));
                else if (!opts.dryRun) console.log(green("✓ Scoped merge complete"));
              }
              if (opts.dryRun) console.log(dim("\n(dry run — nothing written)"));
              return;
            }

            // Full bundle path (existing behavior)
            if (projects) {
              fail("full vault bundles do not support --project; use a scoped bundle or LAN scoped host");
            }
            const payload = opened.payload;
            const localVault = await loadVault();
            const state = await loadSyncState();
            const base = state?.base ?? null;
            if (!base) {
              console.log(
                yellow("⚠ no previous sync snapshot — first sync can only pull/push whole projects"),
              );
            }

            const remoteVault = decryptEnvelope(
              payload.vaultEnc,
              Buffer.from(payload.masterKey, "base64"),
            );

            const first = threeWayMerge(localVault, remoteVault, base, new Map(), "USB");
            const resolutions = await collectResolutions(first.conflicts, forceMode);
            const { merged, report } = threeWayMerge(
              localVault,
              remoteVault,
              base,
              resolutions,
              "USB",
            );

            console.log(`\nSyncing against ${dim(path.basename(latest))}`);
            if (report.length === 0) {
              console.log(green("✓ Already in sync"));
              if (!opts.dryRun) await saveSyncState(localVault);
              return;
            }
            for (const line of report) console.log(`  ${line}`);

            if (opts.dryRun) {
              console.log(dim("\n(dry run — nothing written)"));
              return;
            }

            await saveVault(merged);
            await authenticate("abracadabra: update USB backup");
            const masterKey = await getMasterKey();
            const file = writeBundleToDir(
              path.dirname(latest),
              encryptVault(merged, masterKey),
              masterKey,
              await cachedPassphrase(),
            );
            await saveSyncState(merged);
            console.log(green(`✓ Sync complete — USB refreshed (${path.basename(file)})`));
            return;
          }

          // No backup yet — initial full backup (existing behavior)
          if (projects) {
            fail("no backup found — create a scoped backup with: abra usb backup -f <dir> --project …");
          }
          const localVault = await loadVault();
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
          await saveSyncState(localVault);
          console.log(green(`✓ Initial backup written: ${file}`));
        } catch (err) {
          if (err instanceof LanConflictError) {
            console.error(red(`✗ ${err.message}`));
            for (const c of err.conflicts) {
              console.error(`  ${c.scope}/${c.key} (newest: ${c.newest})`);
            }
            process.exit(1);
          }
          fail(err);
        }
      },
    );
}
