import { describe, it, expect, vi } from "vitest";
import {
  ABRA_REEXEC_ENV,
  isTrustedAgentNode,
  maybeReexecForAgentNode,
} from "./unlock-reexec.js";

describe("isTrustedAgentNode", () => {
  it("requires absolute regular file owned by uid or root, not group/world-writable", () => {
    expect(isTrustedAgentNode("relative/node")).toBe(false);
    expect(
      isTrustedAgentNode("/opt/node", {
        getuid: () => 1000,
        statSync: () =>
          ({
            isFile: () => true,
            mode: 0o755,
            uid: 1000,
          }) as unknown as import("node:fs").Stats,
      }),
    ).toBe(true);
    expect(
      isTrustedAgentNode("/opt/node", {
        getuid: () => 1000,
        statSync: () =>
          ({
            isFile: () => true,
            mode: 0o755,
            uid: 0,
          }) as unknown as import("node:fs").Stats,
      }),
    ).toBe(true);
    expect(
      isTrustedAgentNode("/opt/node", {
        getuid: () => 1000,
        statSync: () =>
          ({
            isFile: () => true,
            mode: 0o775, // group-writable
            uid: 1000,
          }) as unknown as import("node:fs").Stats,
      }),
    ).toBe(false);
    expect(
      isTrustedAgentNode("/opt/node", {
        getuid: () => 1000,
        statSync: () =>
          ({
            isFile: () => true,
            mode: 0o755,
            uid: 999,
          }) as unknown as import("node:fs").Stats,
      }),
    ).toBe(false);
  });
});

describe("maybeReexecForAgentNode", () => {
  it("no-op on non-linux and when ABRA_REEXEC already set", async () => {
    const spawn = vi.fn();
    await maybeReexecForAgentNode({
      platform: "darwin",
      spawnSync: spawn,
    });
    await maybeReexecForAgentNode({
      platform: "linux",
      env: { [ABRA_REEXEC_ENV]: "1" },
      spawnSync: spawn,
    });
    expect(spawn).not.toHaveBeenCalled();
  });

  it("re-execs once when execPath differs and agent node is trusted", async () => {
    const spawn = vi.fn().mockReturnValue({ status: 7, signal: null });
    const exit = vi.fn(((_c: number) => {
      throw new Error("exit");
    }) as (c: number) => never);

    await expect(
      maybeReexecForAgentNode({
        platform: "linux",
        env: {},
        execPath: "/usr/bin/node-a",
        entryPath: "/pkg/dist/index.js",
        argv: ["node", "/pkg/dist/index.js", "unlock"],
        getuid: () => 1000,
        realpathSync: (p) => p,
        existsSync: () => true,
        tryAgent: () => true,
        resolveSocket: () => "/run/user/1000/abra/agent.sock",
        status: async () => ({
          locked: true,
          idleRemainingMs: null,
          maxAgeRemainingMs: null,
          nodePath: "/mise/node",
          entryPath: "/pkg/dist/index.js",
        }),
        statSync: () =>
          ({
            isFile: () => true,
            mode: 0o755,
            uid: 1000,
          }) as unknown as import("node:fs").Stats,
        spawnSync: spawn,
        exit,
      }),
    ).rejects.toThrow("exit");

    expect(spawn).toHaveBeenCalledWith(
      "/mise/node",
      ["/pkg/dist/index.js", "unlock"],
      expect.objectContaining({
        stdio: "inherit",
        env: expect.objectContaining({ [ABRA_REEXEC_ENV]: "1" }),
      }),
    );
    expect(exit).toHaveBeenCalledWith(7);
  });

  it("does not re-exec when node already matches or entry differs", async () => {
    const spawn = vi.fn();
    await maybeReexecForAgentNode({
      platform: "linux",
      env: {},
      execPath: "/mise/node",
      entryPath: "/pkg/dist/index.js",
      realpathSync: (p) => p,
      existsSync: () => true,
      tryAgent: () => true,
      resolveSocket: () => "/sock",
      status: async () => ({
        locked: true,
        idleRemainingMs: null,
        maxAgeRemainingMs: null,
        nodePath: "/mise/node",
        entryPath: "/pkg/dist/index.js",
      }),
      spawnSync: spawn,
    });
    expect(spawn).not.toHaveBeenCalled();

    await maybeReexecForAgentNode({
      platform: "linux",
      env: {},
      execPath: "/usr/bin/node",
      entryPath: "/pkg/dist/index.js",
      realpathSync: (p) => p,
      existsSync: () => true,
      tryAgent: () => true,
      resolveSocket: () => "/sock",
      status: async () => ({
        locked: true,
        idleRemainingMs: null,
        maxAgeRemainingMs: null,
        nodePath: "/mise/node",
        entryPath: "/other/dist/index.js",
      }),
      spawnSync: spawn,
    });
    expect(spawn).not.toHaveBeenCalled();
  });

  it("falls through when agent node is world-writable", async () => {
    const spawn = vi.fn();
    await maybeReexecForAgentNode({
      platform: "linux",
      env: {},
      execPath: "/usr/bin/node",
      entryPath: "/pkg/dist/index.js",
      getuid: () => 1000,
      realpathSync: (p) => p,
      existsSync: () => true,
      tryAgent: () => true,
      resolveSocket: () => "/sock",
      status: async () => ({
        locked: true,
        idleRemainingMs: null,
        maxAgeRemainingMs: null,
        nodePath: "/mise/node",
        entryPath: "/pkg/dist/index.js",
      }),
      statSync: () =>
        ({
          isFile: () => true,
          mode: 0o777,
          uid: 1000,
        }) as unknown as import("node:fs").Stats,
      spawnSync: spawn,
    });
    expect(spawn).not.toHaveBeenCalled();
  });
});
