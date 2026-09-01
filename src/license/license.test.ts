import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  isEthAddress,
  normalizeAddress,
  licenseEnforcementEnabled,
  licenseEnforcementSkipped,
} from "../license/config.js";
import { readActivation, writeActivation, clearActivation } from "../license/store.js";
import { fetchNftBalance } from "../license/verify.js";
import { createActivationChallenge } from "../license/siwe.js";
import { isLicensed } from "../license/index.js";

describe("license", () => {
  const envBackup = { ...process.env };
  let tmpHome = "";

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "abra-lic-"));
    process.env.HOME = tmpHome;
    process.env.ABRA_DIR = path.join(tmpHome, ".abracadabra");
    process.env.ABRA_LICENSE_NFT = "0x0000000000000000000000000000000000000001";
    delete process.env.ABRA_SKIP_LICENSE;
  });

  afterEach(() => {
    process.env = { ...envBackup };
    vi.restoreAllMocks();
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it("validates addresses", () => {
    expect(isEthAddress("0x0000000000000000000000000000000000000001")).toBe(true);
    expect(isEthAddress("0xbad")).toBe(false);
    expect(normalizeAddress("0xAbCdEf0000000000000000000000000000000001")).toBe(
      "0xabcdef0000000000000000000000000000000001",
    );
  });

  it("enforcement off when contract unset or skip set", () => {
    delete process.env.ABRA_LICENSE_NFT;
    expect(licenseEnforcementEnabled()).toBe(false);
    process.env.ABRA_LICENSE_NFT = "0x0000000000000000000000000000000000000001";
    expect(licenseEnforcementEnabled()).toBe(true);
    process.env.ABRA_SKIP_LICENSE = "1";
    expect(licenseEnforcementSkipped()).toBe(true);
    expect(licenseEnforcementEnabled()).toBe(false);
  });

  it("persists activation", () => {
    const rec = writeActivation({
      wallet: "0x00000000000000000000000000000000000000aa",
      balance: 2n,
    });
    expect(rec.wallet).toBe("0x00000000000000000000000000000000000000aa");
    expect(readActivation()?.balance).toBe("2");
    clearActivation();
    expect(readActivation()).toBeNull();
  });

  it("creates activation challenge message", () => {
    const c = createActivationChallenge("0x00000000000000000000000000000000000000aa");
    expect(c.message).toContain("abracadabra.app");
    expect(c.wallet).toBe("0x00000000000000000000000000000000000000aa");
  });

  it("fetchNftBalance parses eth_call result", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ result: "0x0000000000000000000000000000000000000002" }),
      }),
    );
    const bal = await fetchNftBalance("0x00000000000000000000000000000000000000aa");
    expect(bal).toBe(2n);
  });

  it("isLicensed true when skip or activated with balance", async () => {
    process.env.ABRA_SKIP_LICENSE = "1";
    expect(await isLicensed()).toBe(true);

    delete process.env.ABRA_SKIP_LICENSE;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ result: "0x0000000000000000000000000000000000000001" }),
      }),
    );
    writeActivation({ wallet: "0x00000000000000000000000000000000000000aa", balance: 1n });
    expect(await isLicensed()).toBe(true);
  });
});
