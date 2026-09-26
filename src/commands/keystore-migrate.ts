import crypto from "node:crypto";
import fs from "node:fs";
import { NoTerminalError, isNoTerminalError, promptHidden } from "../core/prompt.js";
import { masterKeyFile, vaultFile } from "../core/paths.js";
import { decryptVault } from "../core/vault.js";
import { authenticate as platformAuthenticate } from "../platform/index.js";
import { KeystoreError } from "../platform/types.js";
import { KeytarKeystore } from "../platform/keystore-keytar.js";
import {
  assertVaultPassphraseMin,
  masterKeyFileExists,
  readMasterKeyFile,
  writeMasterKeyFile,
} from "../platform/master-key-file.js";

const SUPPORTED_TARGETS = ["passphrase-file"] as const;
const AUTH_REASON =
  "abracadabra: migrate vault master key from keytar to passphrase-file";

export type MigrateSourceKeystore = {
  getMasterKey(): Promise<Buffer>;
  deleteMasterKey(): Promise<void>;
};

export type MigrateDeps = {
  /** Override `process.platform` (tests). */
  platform?: NodeJS.Platform;
  /** Source keystore — defaults to `new KeytarKeystore()`. */
  sourceKeystore?: MigrateSourceKeystore;
  authenticate?: (reason: string) => Promise<void>;
  promptHidden?: (question: string) => Promise<string>;
  /** Visible/hidden confirm on tty (defaults to promptHidden). */
  confirm?: (question: string) => Promise<string>;
  now?: () => number;
  log?: (msg: string) => void;
  error?: (msg: string) => void;
};

function zero(buf: Buffer | undefined | null): void {
  if (buf && buf.length > 0) buf.fill(0);
}

function formatKeystoreError(err: KeystoreError): Error {
  const hint =
    err.hint ??
    (err.kind === "locked" || err.kind === "unavailable"
      ? "keyring locked / Secret Service unavailable; run from your desktop session"
      : undefined);
  const base = `keystore ${err.kind}: ${err.message}`;
  return new Error(hint ? `${base} (${hint})` : base);
}

function printNextSteps(log: (msg: string) => void): void {
  log("");
  log("Next steps:");
  log("  export ABRA_KEYSTORE=passphrase-file");
  log("  # also add to your shell profile, and for abra-agent systemd:");
  log("  # Environment=ABRA_KEYSTORE=passphrase-file");
  log("  abra doctor");
  log("");
  log("Headless reveals will then prompt for this passphrase (use ssh -t).");
}

/**
 * Move the vault master key from keytar into master.key.enc (v2 wrap).
 * The master key bytes do not change — vault.enc is untouched.
 * Keytar is left intact on any failure; removal is opt-in via --remove-old.
 */
export async function cmdKeystoreMigrate(
  opts: { to: string; removeOld?: boolean },
  deps: MigrateDeps = {},
): Promise<void> {
  const log = deps.log ?? ((msg) => console.log(msg));
  const error = deps.error ?? ((msg) => console.error(msg));
  const prompt = deps.promptHidden ?? promptHidden;
  const confirm = deps.confirm ?? prompt;
  const auth = deps.authenticate ?? platformAuthenticate;
  const platform = deps.platform ?? process.platform;
  const now = deps.now ?? Date.now;

  if (opts.to !== "passphrase-file") {
    throw new Error(
      `Unsupported --to "${opts.to}". Supported targets: ${SUPPORTED_TARGETS.join(", ")}`,
    );
  }

  if (platform === "darwin") {
    throw new Error("migration from the macOS keychain is not supported yet");
  }

  // Only keytar → passphrase-file is supported (implicit source).
  const source = deps.sourceKeystore ?? new KeytarKeystore();

  await auth(AUTH_REASON);

  let keytarKey: Buffer | undefined;
  let fileKey: Buffer | undefined;
  let verifiedThisRun = false;

  try {
    try {
      keytarKey = await source.getMasterKey();
    } catch (e) {
      if (e instanceof KeystoreError && e.kind === "not_found") {
        if (masterKeyFileExists()) {
          log("nothing in keytar; already on passphrase-file");
          return;
        }
        throw new Error("no master key in keytar — nothing to migrate");
      }
      if (e instanceof KeystoreError) throw formatKeystoreError(e);
      throw e;
    }

    if (masterKeyFileExists()) {
      const passphrase = await prompt("Existing vault passphrase (master.key.enc): ");
      try {
        fileKey = readMasterKeyFile(passphrase);
      } catch (e) {
        if (e instanceof Error && e.name === "WrongPassphraseError") {
          throw new Error("wrong passphrase for existing master.key.enc");
        }
        throw e;
      }
      if (
        fileKey.length !== keytarKey.length ||
        !crypto.timingSafeEqual(fileKey, keytarKey)
      ) {
        throw new Error(
          "master.key.enc holds a DIFFERENT key than keytar — refusing; nothing changed",
        );
      }
      if (fs.existsSync(vaultFile())) {
        const raw = JSON.parse(fs.readFileSync(vaultFile(), "utf8"));
        decryptVault(raw, fileKey);
      }
      verifiedThisRun = true;
      log("already migrated (master.key.enc matches keytar)");
    } else {
      const p1 = await prompt("New vault passphrase (12+ characters): ");
      const p2 = await prompt("Confirm new vault passphrase: ");
      if (p1 !== p2) {
        throw new Error("passphrases do not match");
      }
      try {
        assertVaultPassphraseMin(p1);
      } catch (e) {
        throw new Error(e instanceof Error ? e.message : String(e));
      }

      // Re-check immediately before write — never overwrite.
      if (masterKeyFileExists()) {
        throw new Error(
          "master.key.enc appeared while migrating — aborting; nothing written by this run",
        );
      }

      writeMasterKeyFile(keytarKey, p1);

      try {
        fileKey = readMasterKeyFile(p1);
        if (
          fileKey.length !== keytarKey.length ||
          !crypto.timingSafeEqual(fileKey, keytarKey)
        ) {
          throw new Error("readback key mismatch");
        }
        if (fs.existsSync(vaultFile())) {
          const raw = JSON.parse(fs.readFileSync(vaultFile(), "utf8"));
          decryptVault(raw, fileKey);
        }
      } catch (verifyErr) {
        const failedPath = `${masterKeyFile()}.failed-${now()}`;
        try {
          if (fs.existsSync(masterKeyFile())) {
            fs.renameSync(masterKeyFile(), failedPath);
          }
        } catch {
          /* best-effort rename */
        }
        const detail =
          verifyErr instanceof Error ? verifyErr.message : String(verifyErr);
        throw new Error(
          `migration verify failed (${detail}); renamed master.key.enc to ${failedPath}; keytar left intact`,
        );
      }

      verifiedThisRun = true;
      log("✓ Migrated master key to master.key.enc (v2 passphrase wrap)");
      log("  vault.enc unchanged (same master key)");
    }

    if (opts.removeOld) {
      if (!verifiedThisRun) {
        throw new Error("internal: refuse --remove-old without verification in this run");
      }
      let answer: string;
      try {
        answer = await confirm('Type "delete" to remove the master key from keytar: ');
      } catch (e) {
        if (isNoTerminalError(e) || e instanceof NoTerminalError) {
          error("no terminal — refusing to delete keytar entry; keytar copy kept");
          printNextSteps(log);
          return;
        }
        throw e;
      }
      if (answer.trim() !== "delete") {
        log('Confirmation was not "delete" — keytar copy kept');
        printNextSteps(log);
        return;
      }
      await source.deleteMasterKey();
      log("✓ Removed master key from keytar");
    } else {
      log("Keytar copy kept (safer default).");
      log(
        "While it exists, any same-user process with an unlocked keyring can still read the key.",
      );
      log("To remove later: abra keystore migrate --to passphrase-file --remove-old");
    }

    printNextSteps(log);
  } finally {
    zero(keytarKey);
    zero(fileKey);
  }
}
