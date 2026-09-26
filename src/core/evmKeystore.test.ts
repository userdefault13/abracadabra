import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  buildEvmKeystoreV3,
  decryptEvmKeystoreV3,
  scrubCastSecrets,
} from "./evmKeystore.js";
import { runCastWithKeystore } from "./castWithKeystore.js";

describe("scrubCastSecrets", () => {
  it("redacts private key (with/without 0x), password, and paths", () => {
    const privateKey = "0x" + "ab".repeat(32);
    const password = "s3cret-pass";
    const ks = "/tmp/abra-cast-xyz/keystore.json";
    const raw = `err key=${privateKey} bare=${privateKey.slice(2)} pass=${password} file=${ks}`;
    const out = scrubCastSecrets(raw, {
      privateKey,
      password,
      paths: [ks],
    });
    expect(out).not.toContain(privateKey);
    expect(out).not.toContain(privateKey.slice(2));
    expect(out).not.toContain(password);
    expect(out).not.toContain(ks);
    expect(out).toContain("[redacted-key]");
    expect(out).toContain("[redacted-password]");
    expect(out).toContain("[redacted-path]");
  });
});

describe("buildEvmKeystoreV3", () => {
  it("round-trips: decrypt recovers the private key (MAC + aes-128-ctr)", () => {
    const keyHex = randomBytes(32).toString("hex");
    const password = randomBytes(16).toString("base64url");
    const ks = buildEvmKeystoreV3("0x" + keyHex, password);
    expect(ks.version).toBe(3);
    expect(ks).not.toHaveProperty("address");
    expect(ks.crypto.kdf).toBe("scrypt");
    expect(ks.crypto.cipher).toBe("aes-128-ctr");
    expect(ks.crypto.kdfparams.n).toBe(16384);
    expect(decryptEvmKeystoreV3(ks, password)).toBe(keyHex);
  });
});

function castOnPath(): boolean {
  try {
    execFileSync("cast", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

describe("cast keystore integration", () => {
  it.skipIf(!castOnPath())(
    "cast wallet address accepts throwaway keystore via ETH_KEYSTORE/ETH_PASSWORD",
    async () => {
      const keyHex = randomBytes(32).toString("hex");
      const privateKey = "0x" + keyHex;
      const expected = execFileSync("cast", ["wallet", "address", "--private-key", privateKey], {
        encoding: "utf8",
      }).trim();

      const password = randomBytes(16).toString("base64url");
      const ks = buildEvmKeystoreV3(privateKey, password);
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), "abra-cast-it-"));
      await fs.chmod(dir, 0o700);
      const keystorePath = path.join(dir, "keystore.json");
      const passwordPath = path.join(dir, "password");
      try {
        await fs.writeFile(keystorePath, JSON.stringify(ks), { mode: 0o600, flag: "wx" });
        await fs.writeFile(passwordPath, password, { mode: 0o600, flag: "wx" });
        const got = execFileSync("cast", ["wallet", "address"], {
          encoding: "utf8",
          env: {
            ...process.env,
            ETH_KEYSTORE: keystorePath,
            ETH_PASSWORD: passwordPath,
          },
        }).trim();
        expect(got.toLowerCase()).toBe(expected.toLowerCase());
      } finally {
        await fs.rm(dir, { recursive: true, force: true });
      }

      // Also via the production helper
      const { stdout } = await runCastWithKeystore(["wallet", "address"], privateKey);
      expect(stdout.trim().toLowerCase()).toBe(expected.toLowerCase());
    },
  );
});
