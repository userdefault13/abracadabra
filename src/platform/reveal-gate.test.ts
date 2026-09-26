import { describe, it, expect, vi } from "vitest";
import { authorizeReveal } from "./reveal-gate.js";
import { NoTtyApprovalError } from "./auth-passphrase.js";
import { AgentClientError } from "../agent/client.js";

describe("authorizeReveal", () => {
  const caller = {
    exe: "/usr/bin/mcp-client",
    dev: 1,
    ino: 42,
  };

  it("non-passphrase backend → authenticate only", async () => {
    const authenticate = vi.fn(async () => undefined);
    const grantCheck = vi.fn();
    const result = await authorizeReveal({
      reason: "reveal",
      project: "p",
      caller: async () => caller,
      deps: {
        resolveAuthBackend: () => "polkit",
        authenticate,
        grantCheck,
      },
    });
    expect(result).toEqual({ via: "auth" });
    expect(authenticate).toHaveBeenCalledOnce();
    expect(grantCheck).not.toHaveBeenCalled();
  });

  it("passphrase + TTY success → via auth, no grant.check", async () => {
    const authenticate = vi.fn(async () => undefined);
    const grantCheck = vi.fn();
    const result = await authorizeReveal({
      reason: "reveal",
      project: "p",
      caller: async () => caller,
      deps: {
        resolveAuthBackend: () => "passphrase",
        authenticate,
        grantCheck,
        isNoTtyDenial: (e) => e instanceof NoTtyApprovalError,
      },
    });
    expect(result).toEqual({ via: "auth" });
    expect(grantCheck).not.toHaveBeenCalled();
  });

  it("passphrase + no-TTY + no grant → denied with abra grant hint", async () => {
    await expect(
      authorizeReveal({
        reason: "reveal",
        project: "myproj",
        caller: async () => caller,
        deps: {
          resolveAuthBackend: () => "passphrase",
          authenticate: async () => {
            throw new NoTtyApprovalError();
          },
          grantCheck: async () => ({ granted: false }),
          isNoTtyDenial: (e) => e instanceof NoTtyApprovalError,
        },
      }),
    ).rejects.toThrow(/abra grant --project myproj/);
  });

  it("passphrase + no-TTY + matching grant → via grant", async () => {
    const result = await authorizeReveal({
      reason: "reveal",
      project: "p",
      caller: async () => caller,
      deps: {
        resolveAuthBackend: () => "passphrase",
        authenticate: async () => {
          throw new NoTtyApprovalError();
        },
        grantCheck: async () => ({
          granted: true,
          grantId: "abcd1234",
          remainingMs: 1000,
        }),
        isNoTtyDenial: (e) => e instanceof NoTtyApprovalError,
      },
    });
    expect(result).toEqual({ via: "grant", grantId: "abcd1234" });
  });

  it("passphrase + no-TTY + different exe → denied", async () => {
    await expect(
      authorizeReveal({
        reason: "reveal",
        project: "p",
        caller: async () => ({ ...caller, exe: "/other" }),
        deps: {
          resolveAuthBackend: () => "passphrase",
          authenticate: async () => {
            throw new NoTtyApprovalError();
          },
          grantCheck: async () => ({ granted: false }),
          isNoTtyDenial: (e) => e instanceof NoTtyApprovalError,
        },
      }),
    ).rejects.toThrow(/abra grant/);
  });

  it("wrong passphrase error → propagated, grants not consulted", async () => {
    const grantCheck = vi.fn();
    await expect(
      authorizeReveal({
        reason: "reveal",
        project: "p",
        caller: async () => caller,
        deps: {
          resolveAuthBackend: () => "passphrase",
          authenticate: async () => {
            throw new Error("abracadabra: approval denied — wrong passphrase");
          },
          grantCheck,
          isNoTtyDenial: (e) => e instanceof NoTtyApprovalError,
        },
      }),
    ).rejects.toThrow(/wrong passphrase/);
    expect(grantCheck).not.toHaveBeenCalled();
  });

  it("agent unreachable → denied with unlock hint", async () => {
    await expect(
      authorizeReveal({
        reason: "reveal",
        project: "p",
        caller: async () => caller,
        deps: {
          resolveAuthBackend: () => "passphrase",
          authenticate: async () => {
            throw new NoTtyApprovalError();
          },
          grantCheck: async () => {
            throw new AgentClientError("connect refused", "connect");
          },
          isNoTtyDenial: (e) => e instanceof NoTtyApprovalError,
        },
      }),
    ).rejects.toThrow(/abra unlock/);
  });
});
