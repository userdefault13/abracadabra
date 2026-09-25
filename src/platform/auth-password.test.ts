import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { PassThrough } from "node:stream";
import { PasswordPromptAuth } from "./auth-password.js";
import { promptHidden } from "../core/prompt.js";

describe("PasswordPromptAuth", () => {
  const originalIsTTY = process.stdin.isTTY;

  afterEach(() => {
    Object.defineProperty(process.stdin, "isTTY", {
      value: originalIsTTY,
      configurable: true,
    });
    vi.restoreAllMocks();
  });

  it("throws when stdin is not a TTY", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    await expect(new PasswordPromptAuth().authenticate({ reason: "reveal X" })).rejects.toThrow(
      /approval required.*reveal X/,
    );
  });

  it("routes promptHidden to stderr (never stdout)", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: true, configurable: true });
    const promptMod = await import("../core/prompt.js");
    const spy = vi.spyOn(promptMod, "promptHidden").mockResolvedValue("");
    const stdoutSpy = vi.spyOn(process.stdout, "write");

    await new PasswordPromptAuth().authenticate({ reason: "reveal secrets" });

    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0][1]).toBe(process.stderr);
    expect(stdoutSpy).not.toHaveBeenCalled();
  });
});

describe("promptHidden output stream", () => {
  const envBackup = { ...process.env };

  beforeEach(() => {
    process.env.ABRA_SKIP_BIOMETRICS = "1";
    process.env.ABRA_HEADLESS_PASSPHRASE = "test-pass";
  });

  afterEach(() => {
    process.env = { ...envBackup };
    vi.restoreAllMocks();
  });

  it("headless path does not write to stdout", async () => {
    const stdoutSpy = vi.spyOn(process.stdout, "write");
    const err = new PassThrough();
    const chunks: Buffer[] = [];
    err.on("data", (c) => chunks.push(Buffer.from(c)));
    const value = await promptHidden("secret? ", err);
    expect(value).toBe("test-pass");
    expect(stdoutSpy).not.toHaveBeenCalled();
    expect(Buffer.concat(chunks).toString()).toBe("");
  });
});
