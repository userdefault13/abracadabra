import { describe, it, expect, beforeEach, vi } from "vitest";
import crypto from "node:crypto";

const mockKeytar = {
  getPassword: vi.fn(),
  setPassword: vi.fn(),
  deletePassword: vi.fn(),
};

vi.mock("./keytar-loader.js", () => ({
  loadKeytar: vi.fn(async () => mockKeytar),
}));

const { KeytarKeystore, KEYTAR_SERVICE } = await import("./keystore-keytar.js");
const { KeystoreError } = await import("./types.js");

describe("KeytarKeystore", () => {
  beforeEach(() => {
    mockKeytar.getPassword.mockReset();
    mockKeytar.setPassword.mockReset();
    mockKeytar.deletePassword.mockReset();
  });

  it("getMasterKey: getPassword null -> not_found", async () => {
    mockKeytar.getPassword.mockResolvedValue(null);
    const ks = new KeytarKeystore();
    await expect(ks.getMasterKey()).rejects.toMatchObject({
      name: "KeystoreError",
      kind: "not_found",
    });
  });

  it("getMasterKey: getPassword throws locked-like -> locked", async () => {
    mockKeytar.getPassword.mockRejectedValue(new Error("keyring is locked"));
    const ks = new KeytarKeystore();
    await expect(ks.getMasterKey()).rejects.toMatchObject({
      name: "KeystoreError",
      kind: "locked",
    });
  });

  it("getMasterKey: getPassword throws cancelled -> locked", async () => {
    mockKeytar.getPassword.mockRejectedValue(new Error("user cancelled the dialog"));
    const ks = new KeytarKeystore();
    await expect(ks.getMasterKey()).rejects.toMatchObject({ kind: "locked" });
  });

  it("getMasterKey: getPassword throws other -> unavailable", async () => {
    mockKeytar.getPassword.mockRejectedValue(new Error("native module exploded"));
    const ks = new KeytarKeystore();
    await expect(ks.getMasterKey()).rejects.toMatchObject({
      name: "KeystoreError",
      kind: "unavailable",
    });
  });

  it("getMasterKey: valid base64 32-byte -> returns key", async () => {
    const key = crypto.randomBytes(32);
    mockKeytar.getPassword.mockResolvedValue(key.toString("base64"));
    const ks = new KeytarKeystore();
    const got = await ks.getMasterKey();
    expect(got.equals(key)).toBe(true);
    expect(mockKeytar.getPassword).toHaveBeenCalledWith(
      KEYTAR_SERVICE,
      expect.any(String),
    );
  });

  it("getMasterKey: wrong length -> mismatch, not not_found", async () => {
    mockKeytar.getPassword.mockResolvedValue(Buffer.alloc(16).toString("base64"));
    const ks = new KeytarKeystore();
    try {
      await ks.getMasterKey();
      expect.unreachable("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(KeystoreError);
      expect((e as InstanceType<typeof KeystoreError>).kind).toBe("mismatch");
      expect((e as InstanceType<typeof KeystoreError>).kind).not.toBe("not_found");
    }
  });

  it("createMasterKey refuses when entry exists", async () => {
    mockKeytar.getPassword.mockResolvedValue(crypto.randomBytes(32).toString("base64"));
    const ks = new KeytarKeystore();
    await expect(ks.createMasterKey()).rejects.toThrow(/already exists|refusing/i);
    expect(mockKeytar.setPassword).not.toHaveBeenCalled();
  });

  it("createMasterKey stores + reads back when absent", async () => {
    mockKeytar.getPassword
      .mockResolvedValueOnce(null) // existence check
      .mockImplementation(async (_svc: string, _acct: string) => {
        // readback after setPassword — return whatever was last set
        const last = mockKeytar.setPassword.mock.calls.at(-1);
        return last ? (last[2] as string) : null;
      });
    mockKeytar.setPassword.mockResolvedValue(undefined);

    const ks = new KeytarKeystore();
    const got = await ks.createMasterKey();
    expect(got).toBeInstanceOf(Buffer);
    expect(got.length).toBe(32);
    expect(mockKeytar.setPassword).toHaveBeenCalledTimes(1);
    const storedB64 = mockKeytar.setPassword.mock.calls[0][2] as string;
    expect(Buffer.from(storedB64, "base64").equals(got)).toBe(true);
  });

  it("deleteMasterKey: deletes then verifies getPassword null", async () => {
    mockKeytar.deletePassword.mockResolvedValue(true);
    mockKeytar.getPassword.mockResolvedValue(null);
    const ks = new KeytarKeystore();
    await ks.deleteMasterKey();
    expect(mockKeytar.deletePassword).toHaveBeenCalledWith(
      KEYTAR_SERVICE,
      expect.any(String),
    );
    expect(mockKeytar.getPassword).toHaveBeenCalledWith(
      KEYTAR_SERVICE,
      expect.any(String),
    );
  });

  it("deleteMasterKey: readback still present -> unavailable", async () => {
    mockKeytar.deletePassword.mockResolvedValue(true);
    mockKeytar.getPassword.mockResolvedValue(crypto.randomBytes(32).toString("base64"));
    const ks = new KeytarKeystore();
    await expect(ks.deleteMasterKey()).rejects.toMatchObject({
      name: "KeystoreError",
      kind: "unavailable",
    });
  });

  it("deleteMasterKey: locked-like throw -> locked", async () => {
    mockKeytar.deletePassword.mockRejectedValue(new Error("keyring is locked"));
    const ks = new KeytarKeystore();
    await expect(ks.deleteMasterKey()).rejects.toMatchObject({
      name: "KeystoreError",
      kind: "locked",
    });
  });
});
