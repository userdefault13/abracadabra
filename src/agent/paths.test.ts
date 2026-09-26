import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import {
  formatAgentSocketVia,
  isAgentEnabled,
  resolveAgentRuntimeBase,
  resolveAgentSocketPath,
  type AgentPathDeps,
} from "./paths.js";

function fakeStat(partial: {
  isDirectory?: boolean;
  isSymbolicLink?: boolean;
  uid?: number;
  mode?: number;
}): fs.Stats {
  return {
    isDirectory: () => partial.isDirectory ?? true,
    isSymbolicLink: () => partial.isSymbolicLink ?? false,
    isFile: () => !(partial.isDirectory ?? true),
    uid: partial.uid ?? 1000,
    mode: partial.mode ?? 0o40700,
  } as fs.Stats;
}

function enoent(): never {
  const err = new Error("ENOENT") as NodeJS.ErrnoException;
  err.code = "ENOENT";
  throw err;
}

describe("resolveAgentRuntimeBase", () => {
  it("XDG_RUNTIME_DIR set → XDG", () => {
    const r = resolveAgentRuntimeBase({
      env: { XDG_RUNTIME_DIR: "/run/user/1000" },
      platform: "linux",
      getuid: () => 1000,
      lstatSync: () => {
        throw new Error("lstat should not be called when XDG is set");
      },
    });
    expect(r).toEqual({
      dir: "/run/user/1000",
      source: "XDG_RUNTIME_DIR",
      reason: "XDG_RUNTIME_DIR set",
    });
  });

  it("XDG unset + good /run/user/<uid> → fallback", () => {
    const r = resolveAgentRuntimeBase({
      env: {},
      platform: "linux",
      getuid: () => 1000,
      lstatSync: (p) => {
        expect(p).toBe(path.posix.join("/run/user", "1000"));
        return fakeStat({ mode: 0o40700, uid: 1000 });
      },
    });
    expect(r).toEqual({
      dir: "/run/user/1000",
      source: "run-user-fallback",
      reason: "XDG_RUNTIME_DIR unset",
    });
  });

  it("missing (ENOENT) → none", () => {
    const r = resolveAgentRuntimeBase({
      env: {},
      platform: "linux",
      getuid: () => 1000,
      lstatSync: () => enoent(),
    });
    expect(r).toEqual({ dir: null, source: "none", reason: "missing" });
  });

  it("not a directory → none", () => {
    const r = resolveAgentRuntimeBase({
      env: {},
      platform: "linux",
      getuid: () => 1000,
      lstatSync: () => fakeStat({ isDirectory: false, mode: 0o100600 }),
    });
    expect(r.source).toBe("none");
    expect(r.reason).toBe("not a directory");
  });

  it("symlink → none", () => {
    const r = resolveAgentRuntimeBase({
      env: {},
      platform: "linux",
      getuid: () => 1000,
      lstatSync: () => fakeStat({ isSymbolicLink: true }),
    });
    expect(r).toEqual({ dir: null, source: "none", reason: "symlink" });
  });

  it("wrong owner → none", () => {
    const r = resolveAgentRuntimeBase({
      env: {},
      platform: "linux",
      getuid: () => 1000,
      lstatSync: () => fakeStat({ uid: 1001, mode: 0o40700 }),
    });
    expect(r.reason).toBe("owner uid 1001 != 1000");
    expect(r.dir).toBeNull();
  });

  it("group-writable (0o40770) → none", () => {
    const r = resolveAgentRuntimeBase({
      env: {},
      platform: "linux",
      getuid: () => 1000,
      lstatSync: () => fakeStat({ mode: 0o40770 }),
    });
    expect(r.reason).toBe("mode 0o770 has group/other bits");
  });

  it("world-writable (0o40707) → none", () => {
    const r = resolveAgentRuntimeBase({
      env: {},
      platform: "linux",
      getuid: () => 1000,
      lstatSync: () => fakeStat({ mode: 0o40707 }),
    });
    expect(r.reason).toBe("mode 0o707 has group/other bits");
  });

  it("group-readable (0o40750) → none", () => {
    const r = resolveAgentRuntimeBase({
      env: {},
      platform: "linux",
      getuid: () => 1000,
      lstatSync: () => fakeStat({ mode: 0o40750 }),
    });
    expect(r.reason).toBe("mode 0o750 has group/other bits");
  });

  it("getuid undefined → none", () => {
    const r = resolveAgentRuntimeBase({
      env: {},
      platform: "linux",
      getuid: () => undefined,
      lstatSync: () => {
        throw new Error("lstat should not run");
      },
    });
    expect(r).toEqual({
      dir: null,
      source: "none",
      reason: "getuid unavailable",
    });
  });

  it("darwin with XDG unset → none", () => {
    const r = resolveAgentRuntimeBase({
      env: {},
      platform: "darwin",
      getuid: () => 501,
      lstatSync: () => {
        throw new Error("lstat should not run on darwin");
      },
    });
    expect(r).toEqual({
      dir: null,
      source: "none",
      reason: "XDG_RUNTIME_DIR unset",
    });
  });

  it("win32 with XDG unset → none", () => {
    const r = resolveAgentRuntimeBase({
      env: {},
      platform: "win32",
      getuid: () => undefined,
      lstatSync: () => {
        throw new Error("lstat should not run on win32");
      },
    });
    expect(r.source).toBe("none");
    expect(r.dir).toBeNull();
  });

  it("ABRA_AGENT_SOCKET wins as source", () => {
    const r = resolveAgentRuntimeBase({
      env: {
        ABRA_AGENT_SOCKET: "/tmp/abra-test/agent.sock",
        XDG_RUNTIME_DIR: "/run/user/1000",
      },
      platform: "linux",
      getuid: () => 1000,
      lstatSync: () => {
        throw new Error("lstat should not run");
      },
    });
    expect(r.source).toBe("ABRA_AGENT_SOCKET");
    expect(r.reason).toBe("ABRA_AGENT_SOCKET set");
    expect(r.dir).toBe(path.dirname(path.resolve("/tmp/abra-test/agent.sock")));
  });
});

describe("isAgentEnabled / resolveAgentSocketPath with fallback", () => {
  const goodFallback: AgentPathDeps = {
    env: {},
    platform: "linux",
    getuid: () => 1000,
    lstatSync: () => fakeStat({ mode: 0o40700, uid: 1000 }),
  };

  it("fallback enables agent and resolves socket via path.posix", () => {
    expect(isAgentEnabled(goodFallback)).toBe(true);
    expect(resolveAgentSocketPath(goodFallback)).toBe(
      path.posix.join("/run/user/1000", "abra", "agent.sock"),
    );
    expect(resolveAgentSocketPath(goodFallback)).toBe(
      "/run/user/1000/abra/agent.sock",
    );
  });

  it("ABRA_AGENT_SOCKET still wins for socket path", () => {
    const deps: AgentPathDeps = {
      ...goodFallback,
      env: { ABRA_AGENT_SOCKET: "/tmp/custom.sock" },
    };
    // Fallback still enables (XDG/fallback check ignores the socket override).
    expect(isAgentEnabled(deps)).toBe(true);
    expect(resolveAgentSocketPath(deps)).toBe(path.resolve("/tmp/custom.sock"));
  });

  it("ABRA_AGENT_SOCKET alone (no XDG, bad fallback) does not enable", () => {
    const deps: AgentPathDeps = {
      env: { ABRA_AGENT_SOCKET: "/tmp/custom.sock" },
      platform: "linux",
      getuid: () => 1000,
      lstatSync: () => enoent(),
    };
    expect(isAgentEnabled(deps)).toBe(false);
    expect(resolveAgentSocketPath(deps)).toBe(path.resolve("/tmp/custom.sock"));
  });

  it("ABRA_AGENT=0 still disables even with valid fallback", () => {
    expect(
      isAgentEnabled({
        ...goodFallback,
        env: { ABRA_AGENT: "0" },
      }),
    ).toBe(false);
  });

  it("XDG unset + missing fallback → isAgentEnabled false", () => {
    const deps: AgentPathDeps = {
      env: {},
      platform: "linux",
      getuid: () => 1000,
      lstatSync: () => enoent(),
    };
    expect(isAgentEnabled(deps)).toBe(false);
    expect(() => resolveAgentSocketPath(deps)).toThrow(/\/run\/user\/<uid>/);
  });

  it("XDG unset + wrong owner → isAgentEnabled false", () => {
    expect(
      isAgentEnabled({
        env: {},
        platform: "linux",
        getuid: () => 1000,
        lstatSync: () => fakeStat({ uid: 1001, mode: 0o40700 }),
      }),
    ).toBe(false);
  });

  it("XDG unset + group/other bits → isAgentEnabled false", () => {
    expect(
      isAgentEnabled({
        env: {},
        platform: "linux",
        getuid: () => 1000,
        lstatSync: () => fakeStat({ mode: 0o40770 }),
      }),
    ).toBe(false);
    expect(
      isAgentEnabled({
        env: {},
        platform: "linux",
        getuid: () => 1000,
        lstatSync: () => fakeStat({ mode: 0o40707 }),
      }),
    ).toBe(false);
  });

  it("win32 stays off even with valid /run/user fallback deps", () => {
    expect(
      isAgentEnabled({
        env: {},
        platform: "win32",
        getuid: () => 1000,
        lstatSync: () => fakeStat({ mode: 0o40700, uid: 1000 }),
      }),
    ).toBe(false);
  });

  it("formatAgentSocketVia covers sources", () => {
    expect(formatAgentSocketVia("run-user-fallback", "XDG_RUNTIME_DIR unset")).toBe(
      "via /run/user/<uid> fallback: XDG_RUNTIME_DIR unset",
    );
    expect(formatAgentSocketVia("XDG_RUNTIME_DIR", "XDG_RUNTIME_DIR set")).toBe(
      "via XDG_RUNTIME_DIR: XDG_RUNTIME_DIR set",
    );
  });
});
