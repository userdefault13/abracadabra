import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  MASTER_KEY_FORMAT,
  V2_SCRYPT_N,
  assertVaultPassphraseMin,
  loadMasterKeyFileRaw,
  masterKeyAad,
  openMasterKeyFile,
  passphraseCodePointLength,
  readMasterKeyFile,
  sealMasterKeyFile,
  setDefaultKdfForTests,
  validateKdfParams,
  WrongPassphraseError,
} from "./master-key-file.js";

describe("master-key-file", () => {
  const envBackup = { ...process.env };
  let tmpDir = "";

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "abra-mkf-"));
    process.env.ABRA_DIR = tmpDir;
    setDefaultKdfForTests({ N: 16384 });
  });

  afterEach(() => {
    process.env = { ...envBackup };
    setDefaultKdfForTests(null);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("v2 round-trips a 32-byte master key (fast test N)", () => {
    const key = crypto.randomBytes(32);
    const file = sealMasterKeyFile(key, "test-passphrase-12", {
      kdf: { N: 16384, r: 8, p: 1 },
    });
    expect(file.version).toBe(2);
    expect(file.kdf.N).toBe(16384);
    const restored = openMasterKeyFile(file, "test-passphrase-12");
    expect(restored.equals(key)).toBe(true);
  });

  it("rejects wrong passphrase as WrongPassphraseError", () => {
    const file = sealMasterKeyFile(crypto.randomBytes(32), "right-pass-12", {
      kdf: { N: 16384 },
    });
    expect(() => openMasterKeyFile(file, "wrong-pass-12")).toThrow(WrongPassphraseError);
  });

  it("AAD tamper (version / kdf / format) fails authentication", () => {
    const key = crypto.randomBytes(32);
    const file = sealMasterKeyFile(key, "aad-tamper-test", { kdf: { N: 16384 } });
    expect(file.version).toBe(2);

    const bumpVersion = { ...file, version: 1 as const };
    expect(() => openMasterKeyFile(bumpVersion as typeof file, "aad-tamper-test")).toThrow();

    const bumpN = {
      ...file,
      kdf: { ...file.kdf, N: 32768 },
    };
    expect(() => openMasterKeyFile(bumpN, "aad-tamper-test")).toThrow();

    const bumpFormat = { ...file, format: "not-abracadabra" as typeof file.format };
    expect(() => openMasterKeyFile(bumpFormat, "aad-tamper-test")).toThrow();
  });

  it("v1 file opens and rewraps to v2 when passphrase >= 12", () => {
    const key = crypto.randomBytes(32);
    const pass = "long-enough-12";
    const v1 = sealMasterKeyFile(key, pass, { version: 1 });
    expect(v1.version).toBe(1);
    const file = path.join(tmpDir, "master.key.enc");
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(file, JSON.stringify(v1, null, 2), { mode: 0o600 });

    const opened = readMasterKeyFile(pass);
    expect(opened.equals(key)).toBe(true);
    const onDisk = loadMasterKeyFileRaw();
    expect(onDisk.version).toBe(2);
    // Rewrap uses test default N unless cleared — still version 2 + AAD.
    expect(onDisk.kdf.N).toBe(16384);
    expect(openMasterKeyFile(onDisk, pass).equals(key)).toBe(true);
  });

  it("v1 file stays v1 with stderr warning when passphrase < 12", () => {
    const key = crypto.randomBytes(32);
    const pass = "short-pw"; // 8 code points
    const v1 = sealMasterKeyFile(key, pass, { version: 1 });
    const file = path.join(tmpDir, "master.key.enc");
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(file, JSON.stringify(v1, null, 2), { mode: 0o600 });

    const errSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const opened = readMasterKeyFile(pass);
    expect(opened.equals(key)).toBe(true);
    expect(loadMasterKeyFileRaw().version).toBe(1);
    expect(errSpy.mock.calls.some((c) => String(c[0]).includes("shorter than 12"))).toBe(true);
    errSpy.mockRestore();
  });

  it("enforces 12-char minimum at creation (code points after NFKC)", () => {
    expect(passphraseCodePointLength("a".repeat(11))).toBe(11);
    expect(passphraseCodePointLength("a".repeat(12))).toBe(12);
    // NFKC: ﬁ (U+FB01) → fi (2 code points)
    expect(passphraseCodePointLength("ﬁ".repeat(6))).toBe(12);
    expect(() => assertVaultPassphraseMin("a".repeat(11))).toThrow(/at least 12/);
    expect(() => assertVaultPassphraseMin("a".repeat(12))).not.toThrow();
  });

  it("validates kdf params (rejects absurd N/r/p)", () => {
    const base = {
      algo: "scrypt" as const,
      salt: crypto.randomBytes(16).toString("base64"),
      N: 16384,
      r: 8,
      p: 1,
      keyLen: 32,
    };
    expect(() => validateKdfParams(base)).not.toThrow();
    expect(() => validateKdfParams({ ...base, N: 1000 })).toThrow(/Invalid scrypt N/);
    expect(() => validateKdfParams({ ...base, N: 2 ** 21 })).toThrow(/Invalid scrypt N/);
    expect(() => validateKdfParams({ ...base, r: 0 })).toThrow(/Invalid scrypt r/);
    expect(() => validateKdfParams({ ...base, r: 33 })).toThrow(/Invalid scrypt r/);
    expect(() => validateKdfParams({ ...base, p: 0 })).toThrow(/Invalid scrypt p/);
    expect(() => validateKdfParams({ ...base, p: 17 })).toThrow(/Invalid scrypt p/);
    expect(() =>
      validateKdfParams({ ...base, salt: crypto.randomBytes(8).toString("base64") }),
    ).toThrow(/salt/);
  });

  it("masterKeyAad is stable for identical headers", () => {
    const kdf = {
      algo: "scrypt" as const,
      salt: "YWJjZGVmZ2hpams1bW4=",
      N: V2_SCRYPT_N,
      r: 8,
      p: 1,
      keyLen: 32,
    };
    const a = masterKeyAad({ format: MASTER_KEY_FORMAT, version: 2, kdf });
    const b = masterKeyAad({ format: MASTER_KEY_FORMAT, version: 2, kdf });
    expect(a.equals(b)).toBe(true);
  });

  it("exercises real v2 scrypt params once (N=2^17)", () => {
    setDefaultKdfForTests(null); // production defaults
    const key = crypto.randomBytes(32);
    const pass = "real-v2-params!!";
    const t0 = performance.now();
    const file = sealMasterKeyFile(key, pass);
    const t1 = performance.now();
    expect(file.version).toBe(2);
    expect(file.kdf.N).toBe(V2_SCRYPT_N);
    expect(openMasterKeyFile(file, pass).equals(key)).toBe(true);
    expect(t1 - t0).toBeGreaterThan(0);
  });
});
