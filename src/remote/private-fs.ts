import fs from "node:fs";
import path from "node:path";
import { abraDir } from "../core/paths.js";

const isPosix = process.platform !== "win32";

export const REMOTE_DIRNAME = "remote";

export function remoteDir(base: string = abraDir()): string {
  return path.join(base, REMOTE_DIRNAME);
}

/**
 * mkdir -p with 0700. On POSIX, fail closed if the dir is a symlink, not a
 * directory, owned by someone else, or group/world-accessible.
 */
export function ensureRemoteDir(base: string = abraDir(), uid = process.getuid?.()): void {
  const dir = remoteDir(base);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  assertPrivatePath(dir, { expectDir: true, uid });
}

/** Atomic 0600 write (tmp + rename) into an already-checked remote dir. */
export function writePrivateFile(file: string, data: string): void {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, data, { mode: 0o600, flag: "wx" });
  try {
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
}

/**
 * Fail closed on POSIX if path is a symlink, wrong type, wrong owner, or
 * group/world-readable. On win32, only type checks (no mode/uid).
 */
export function assertPrivatePath(
  target: string,
  opts: { expectDir: boolean; uid?: number },
): void {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(target);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err.code === "ENOENT") throw e;
    throw new Error(`cannot stat remote path: ${path.basename(target)}`);
  }

  if (st.isSymbolicLink()) {
    throw new Error(`remote path must not be a symlink: ${path.basename(target)}`);
  }
  if (opts.expectDir) {
    if (!st.isDirectory()) {
      throw new Error(`remote path is not a directory: ${path.basename(target)}`);
    }
  } else if (!st.isFile()) {
    throw new Error(`remote path is not a file: ${path.basename(target)}`);
  }

  if (!isPosix) return;

  const uid = opts.uid ?? process.getuid?.();
  if (uid === undefined) {
    throw new Error("remote store requires a POSIX uid (process.getuid)");
  }
  if (st.uid !== uid) {
    throw new Error(
      `remote path owner mismatch (uid ${st.uid} != ${uid}): ${path.basename(target)}`,
    );
  }
  const mode = st.mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(
      `remote path must not be group/world-readable (got 0o${mode.toString(8)}): ${path.basename(target)}`,
    );
  }
}

/** Read a private file after failing closed on its parent dir + the file itself. */
export function readPrivateFile(file: string, base: string = abraDir()): string {
  ensureRemoteDir(base);
  assertPrivatePath(file, { expectDir: false });
  return fs.readFileSync(file, "utf8");
}
