import { describe, it, expect, vi } from "vitest";
import crypto from "node:crypto";
import type { PlatformKeystore } from "../platform/types.js";
import { KeystoreError } from "../platform/types.js";
import { resolveMasterKey } from "./masterKey.js";

function fakeKey(fill = 7): Buffer {
  return Buffer.alloc(32, fill);
}

describe("resolveMasterKey", () => {
  it("not_found + no vault -> mints via createMasterKey once", async () => {
    const minted = fakeKey(1);
    const createMasterKey = vi.fn(async () => minted);
    const storeMasterKey = vi.fn();
    const keystore: PlatformKeystore = {
      id: "test",
      getOrCreateMasterKey: vi.fn(),
      storeMasterKey,
      getMasterKey: vi.fn(async () => {
        throw new KeystoreError("not_found", "missing");
      }),
      createMasterKey,
    };

    const got = await resolveMasterKey(keystore, { vaultExists: () => false });
    expect(got.equals(minted)).toBe(true);
    expect(createMasterKey).toHaveBeenCalledTimes(1);
    expect(storeMasterKey).not.toHaveBeenCalled();
  });

  it("not_found + existing vault -> throws, never mints", async () => {
    const createMasterKey = vi.fn(async () => fakeKey());
    const storeMasterKey = vi.fn();
    const keystore: PlatformKeystore = {
      id: "test",
      getOrCreateMasterKey: vi.fn(),
      storeMasterKey,
      getMasterKey: vi.fn(async () => {
        throw new KeystoreError("not_found", "missing");
      }),
      createMasterKey,
    };

    await expect(
      resolveMasterKey(keystore, { vaultExists: () => true }),
    ).rejects.toMatchObject({ kind: "not_found" });
    expect(createMasterKey).not.toHaveBeenCalled();
    expect(storeMasterKey).not.toHaveBeenCalled();
  });

  it("locked -> throws, never mints", async () => {
    const createMasterKey = vi.fn(async () => fakeKey());
    const storeMasterKey = vi.fn();
    const keystore: PlatformKeystore = {
      id: "test",
      getOrCreateMasterKey: vi.fn(),
      storeMasterKey,
      getMasterKey: vi.fn(async () => {
        throw new KeystoreError("locked", "keyring locked");
      }),
      createMasterKey,
    };

    await expect(
      resolveMasterKey(keystore, { vaultExists: () => false }),
    ).rejects.toMatchObject({ kind: "locked" });
    expect(createMasterKey).not.toHaveBeenCalled();
    expect(storeMasterKey).not.toHaveBeenCalled();
  });

  it("denied -> throws, never mints", async () => {
    const createMasterKey = vi.fn(async () => fakeKey());
    const storeMasterKey = vi.fn();
    const keystore: PlatformKeystore = {
      id: "test",
      getOrCreateMasterKey: vi.fn(),
      storeMasterKey,
      getMasterKey: vi.fn(async () => {
        throw new KeystoreError("denied", "permission denied");
      }),
      createMasterKey,
    };

    await expect(
      resolveMasterKey(keystore, { vaultExists: () => false }),
    ).rejects.toMatchObject({ kind: "denied" });
    expect(createMasterKey).not.toHaveBeenCalled();
    expect(storeMasterKey).not.toHaveBeenCalled();
  });

  it("unknown plain Error -> throws as unavailable, never mints", async () => {
    const createMasterKey = vi.fn(async () => fakeKey());
    const storeMasterKey = vi.fn();
    const keystore: PlatformKeystore = {
      id: "test",
      getOrCreateMasterKey: vi.fn(),
      storeMasterKey,
      getMasterKey: vi.fn(async () => {
        throw new Error("boom from backend");
      }),
      createMasterKey,
    };

    await expect(
      resolveMasterKey(keystore, { vaultExists: () => false }),
    ).rejects.toMatchObject({
      name: "KeystoreError",
      kind: "unavailable",
      message: "boom from backend",
    });
    expect(createMasterKey).not.toHaveBeenCalled();
    expect(storeMasterKey).not.toHaveBeenCalled();
  });

  it("success path returns key", async () => {
    const key = fakeKey(9);
    const createMasterKey = vi.fn();
    const keystore: PlatformKeystore = {
      id: "test",
      getOrCreateMasterKey: vi.fn(),
      storeMasterKey: vi.fn(),
      getMasterKey: vi.fn(async () => key),
      createMasterKey,
    };

    const got = await resolveMasterKey(keystore, { vaultExists: () => true });
    expect(got.equals(key)).toBe(true);
    expect(createMasterKey).not.toHaveBeenCalled();
  });

  it("backend without getMasterKey falls back to getOrCreateMasterKey", async () => {
    const key = fakeKey(3);
    const getOrCreateMasterKey = vi.fn(async () => key);
    const keystore: PlatformKeystore = {
      id: "legacy",
      getOrCreateMasterKey,
      storeMasterKey: vi.fn(),
    };

    const got = await resolveMasterKey(keystore);
    expect(got.equals(key)).toBe(true);
    expect(getOrCreateMasterKey).toHaveBeenCalledTimes(1);
  });

  it("not_found + no vault + no createMasterKey -> storeMasterKey of fresh random key", async () => {
    const storeMasterKey = vi.fn(async () => {});
    const keystore: PlatformKeystore = {
      id: "test",
      getOrCreateMasterKey: vi.fn(),
      storeMasterKey,
      getMasterKey: vi.fn(async () => {
        throw new KeystoreError("not_found", "missing");
      }),
    };

    const got = await resolveMasterKey(keystore, { vaultExists: () => false });
    expect(got).toBeInstanceOf(Buffer);
    expect(got.length).toBe(32);
    expect(storeMasterKey).toHaveBeenCalledTimes(1);
    expect(storeMasterKey.mock.calls[0][0].equals(got)).toBe(true);
  });
});
