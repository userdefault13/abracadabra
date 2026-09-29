import { describe, it, expect, vi } from "vitest";
import type fs from "node:fs";
import { resolveUnlockState } from "./unlock.js";
import { shouldTryAgent } from "../agent/client.js";
import type { AgentPathDeps } from "../agent/paths.js";

const pf = (vaultLocked: boolean) => () => ({ keystore: "passphrase-file", vaultLocked });

function runUserStat(mode: number, uid = 1000): fs.Stats {
  return {
    isDirectory: () => true,
    isSymbolicLink: () => false,
    isFile: () => false,
    uid,
    mode,
  } as fs.Stats;
}

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

  it("XDG_RUNTIME_DIR unset + valid /run/user/<uid> fallback → agent", async () => {
    const lstatSync = vi.fn(() => runUserStat(0o40700));
    const pathDeps: AgentPathDeps = {
      env: {},
      platform: "linux",
      getuid: () => 1000,
      lstatSync,
    };
    const r = await resolveUnlockState({
      info: pf(true),
      tryAgent: () => shouldTryAgent(pathDeps),
      status: async () => ({ locked: false }),
    });
    expect(r.state).toBe("agent");
    expect(lstatSync).toHaveBeenCalledWith("/run/user/1000");
  });

  it("XDG_RUNTIME_DIR unset + group-accessible /run/user/<uid> → locked (agent not tried)", async () => {
    const status = vi.fn(async () => ({ locked: false }));
    const r = await resolveUnlockState({
      info: pf(true),
      tryAgent: () =>
        shouldTryAgent({
          env: {},
          platform: "linux",
          getuid: () => 1000,
          lstatSync: () => runUserStat(0o40750),
        }),
      status,
    });
    expect(r.state).toBe("locked");
    expect(status).not.toHaveBeenCalled();
  });
});
