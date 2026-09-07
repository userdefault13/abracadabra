import { execFile, spawn } from "node:child_process";
import crypto from "node:crypto";
import os from "node:os";
import { promisify } from "node:util";
import type { PlatformKeystore } from "./types.js";

const execFileAsync = promisify(execFile);

const SERVICE = "abracadabra-master-key";
const ACCOUNT = os.userInfo().username;

/** `security` exit status for errSecItemNotFound: the item simply does not exist. */
export const SEC_ITEM_NOT_FOUND = 44;

export class KeychainError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
  ) {
    super(message);
    this.name = "KeychainError";
  }

  /** True only when the Keychain says the item is absent — never for access errors. */
  get notFound(): boolean {
    return this.status === SEC_ITEM_NOT_FOUND || /could not be found/i.test(this.message);
  }
}

/**
 * Remove whatever follows a `-w` flag. A secret must never ride along in an
 * error message: the CLI prints thrown errors verbatim, and that is exactly
 * how a vault master key ended up in a terminal transcript.
 */
export function scrubSecurityText(text: string): string {
  return text.replace(/(-w)\s+("[^"]*"|\S+)/g, "$1 <redacted>");
}

function toKeychainError(verb: string, e: unknown): KeychainError {
  const err = e as { code?: unknown; stderr?: unknown; message?: unknown };
  const status = typeof err?.code === "number" ? err.code : null;
  const detail = scrubSecurityText(String(err?.stderr || err?.message || e)).trim();
  return new KeychainError(`security ${verb} failed${status != null ? ` (${status})` : ""}: ${detail}`, status);
}

/** Run `security` with argv that carries no secret (reads only). */
async function runSecurity(args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync("security", args);
    return stdout;
  } catch (e) {
    throw toKeychainError(args[0] ?? "security", e);
  }
}

/**
 * Run one `security` command through its interactive mode, feeding the whole
 * command line on stdin. This is the only way to hand `security` a secret
 * without putting it on argv — where `ps` can read it for as long as the
 * process runs, and where any error path would echo it.
 *
 * `security -i` exits with the failing command's status, so callers still get
 * a real exit code.
 */
function runSecurityStdin(verb: string, line: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn("security", ["-i"], { stdio: ["pipe", "ignore", "pipe"] });
    let stderr = "";
    child.stderr?.on("data", (d) => {
      stderr += String(d);
    });
    child.on("error", (e) => reject(toKeychainError(verb, e)));
    child.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new KeychainError(`security ${verb} failed (${code}): ${scrubSecurityText(stderr).trim()}`, code));
    });
    child.stdin?.end(`${line}\n`);
  });
}

/** Quote an argument for `security -i`'s shell-like line parser. */
const q = (s: string): string => `"${s.replace(/(["\\$`])/g, "\\$1")}"`;

export class MacOSKeychainKeystore implements PlatformKeystore {
  readonly id = "macos-keychain";

  async getOrCreateMasterKey(): Promise<Buffer> {
    let stored: string | null = null;
    try {
      stored = await runSecurity(["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"]);
    } catch (e) {
      // Only a genuinely missing item means "first run". Anything else — a
      // locked keychain, "User interaction is not allowed" from an ssh session,
      // a transient failure — must NOT be answered by minting a new key:
      // storing it (with -U) would replace the key the vault is encrypted with,
      // and every secret would become unreadable.
      if (!(e instanceof KeychainError) || !e.notFound) {
        const why = e instanceof Error ? e.message : String(e);
        throw new Error(
          `Keychain master key is not accessible: ${why}\n` +
            `If this is an ssh or headless session, run abra from a GUI login on this Mac ` +
            `(or set ABRA_KEYSTORE=passphrase). Refusing to create a new master key over an existing vault.`,
        );
      }
      const key = crypto.randomBytes(32);
      await this.storeMasterKey(key);
      return key;
    }
    const key = Buffer.from(stored.trim(), "base64");
    if (key.length !== 32) throw new Error("Corrupt master key in Keychain");
    return key;
  }

  async storeMasterKey(key: Buffer): Promise<void> {
    await runSecurityStdin(
      "add-generic-password",
      `add-generic-password -s ${q(SERVICE)} -a ${q(ACCOUNT)} -w ${q(key.toString("base64"))} -U`,
    );
    const stdout = await runSecurity(["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"]);
    const stored = Buffer.from(stdout.trim(), "base64");
    if (!stored.equals(key)) {
      throw new Error("Failed to store master key in Keychain");
    }
  }
}
