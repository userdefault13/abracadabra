import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import { openMasterKeyFile, sealMasterKeyFile } from "./master-key-file.js";

describe("master-key-file", () => {
  it("seals and opens a 32-byte master key", () => {
    const key = crypto.randomBytes(32);
    const file = sealMasterKeyFile(key, "test-passphrase");
    const restored = openMasterKeyFile(file, "test-passphrase");
    expect(restored.equals(key)).toBe(true);
  });

  it("rejects wrong passphrase", () => {
    const file = sealMasterKeyFile(crypto.randomBytes(32), "right");
    expect(() => openMasterKeyFile(file, "wrong")).toThrow();
  });
});
