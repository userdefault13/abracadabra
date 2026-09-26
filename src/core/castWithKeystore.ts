import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { randomBytes } from "node:crypto";
import { buildEvmKeystoreV3, scrubCastSecrets } from "./evmKeystore.js";

const execFileAsync = promisify(execFile);

export type CastExecFn = (
  command: string,
  args: readonly string[],
  options: { env: NodeJS.ProcessEnv; maxBuffer?: number },
) => Promise<{ stdout: string; stderr: string }>;

const defaultCastExec: CastExecFn = async (command, args, options) => {
  const result = await execFileAsync(command, [...args], {
    env: options.env,
    maxBuffer: options.maxBuffer,
  });
  return { stdout: result.stdout, stderr: result.stderr };
};

function castMissingHint(err: unknown): Error | null {
  if (err instanceof Error && "code" in err && (err as { code?: string }).code === "ENOENT") {
    return new Error(
      "foundry's `cast` not found on PATH. Install: curl -L https://foundry.paradigm.xyz | sh && foundryup",
    );
  }
  return null;
}

function scrubError(err: unknown, secrets: Parameters<typeof scrubCastSecrets>[1]): Error {
  const hint = castMissingHint(err);
  if (hint) return hint;
  const stderr =
    err && typeof err === "object" && "stderr" in err
      ? String((err as { stderr: unknown }).stderr)
      : "";
  const msg = err instanceof Error ? err.message : String(err);
  const raw = stderr.trim() || msg;
  return new Error(scrubCastSecrets(raw, secrets));
}

/**
 * Run `cast <args…>` signed with a throwaway Web3 v3 keystore.
 *
 * Foundry 1.5 reads `ETH_KEYSTORE` (file) and `ETH_PASSWORD` (password-*file* path).
 * Neither the private key nor the password is placed on argv.
 * Temp dir (0700) is always removed.
 */
export async function runCastWithKeystore(
  args: readonly string[],
  privateKey: string,
  opts: { exec?: CastExecFn; maxBuffer?: number } = {},
): Promise<{ stdout: string; stderr: string }> {
  const exec = opts.exec ?? defaultCastExec;
  const password = randomBytes(24).toString("base64url");
  const keystore = buildEvmKeystoreV3(privateKey, password);
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "abra-cast-"));
  await fs.chmod(dir, 0o700);
  const keystorePath = path.join(dir, "keystore.json");
  const passwordPath = path.join(dir, "password");
  const secrets = {
    privateKey,
    password,
    paths: [keystorePath, passwordPath, dir],
  };

  try {
    await fs.writeFile(keystorePath, JSON.stringify(keystore), { mode: 0o600, flag: "wx" });
    await fs.writeFile(passwordPath, password, { mode: 0o600, flag: "wx" });

    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.ETH_FROM;
    delete env.ETH_KEYSTORE_ACCOUNT;
    delete env.ETH_PRIVATE_KEY;
    env.ETH_KEYSTORE = keystorePath;
    // cast 1.5: ETH_PASSWORD is the password-*file* path (not the password string)
    env.ETH_PASSWORD = passwordPath;

    try {
      return await exec("cast", args, {
        env,
        maxBuffer: opts.maxBuffer ?? 2 * 1024 * 1024,
      });
    } catch (err) {
      throw scrubError(err, secrets);
    }
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}
