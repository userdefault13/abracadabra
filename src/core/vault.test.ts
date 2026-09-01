import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import { emptyVault, encryptVault, decryptEnvelope, assertProject } from "./vault.js";

describe("vault", () => {
  it("encrypts and decrypts a vault roundtrip", () => {
    const key = crypto.randomBytes(32);
    const vault = emptyVault();
    vault.projects.demo = {
      createdAt: Date.now(),
      vars: {
        API_KEY: { value: "secret-value", secret: true, updatedAt: 1 },
      },
    };

    const enc = encryptVault(vault, key);
    const restored = decryptEnvelope(enc, key);

    expect(restored.projects.demo.vars.API_KEY.value).toBe("secret-value");
    expect(restored.version).toBe(1);
  });

  it("rejects tampered ciphertext", () => {
    const key = crypto.randomBytes(32);
    const enc = encryptVault(emptyVault(), key);
    const tagBuf = Buffer.from(enc.tag, "base64");
    tagBuf[0] ^= 0xff;
    enc.tag = tagBuf.toString("base64");

    expect(() => decryptEnvelope(enc, key)).toThrow();
  });

  it("assertProject throws for missing project", () => {
    expect(() => assertProject(emptyVault(), "nope")).toThrow(/not found/);
  });
});
