import { describe, it, expect } from "vitest";
import { resolveUnlockState } from "./unlock.js";

const pf = (vaultLocked: boolean) => () => ({ keystore: "passphrase-file", vaultLocked });

describe("resolveUnlockState", () => {
  it("not applicable off passphrase-file", async () => {
    const r = await resolveUnlockState({ info: () => ({ keystore: "keytar", vaultLocked: false }) });
    expect(r.state).toBe("not-applicable");
  });

  it("this process's own session counts", async () => {
    const r = await resolveUnlockState({ info: pf(false), tryAgent: () => false });
    expect(r.state).toBe("session");
  });

  it("a fresh process is unlocked when abra-agent holds the key", async () => {
    const r = await resolveUnlockState({
      info: pf(true),
      tryAgent: () => true,
      status: async () => ({ locked: false }),
    });
    expect(r.state).toBe("agent");
  });

  it("locked when the agent is locked, down, or disabled", async () => {
    const locked = await resolveUnlockState({
      info: pf(true),
      tryAgent: () => true,
      status: async () => ({ locked: true }),
    });
    expect(locked.state).toBe("locked");
    const down = await resolveUnlockState({
      info: pf(true),
      tryAgent: () => true,
      status: async () => {
        throw new Error("ECONNREFUSED");
      },
    });
    expect(down.state).toBe("locked");
    const off = await resolveUnlockState({ info: pf(true), tryAgent: () => false });
    expect(off.state).toBe("locked");
  });
});
