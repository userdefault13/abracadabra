import { describe, it, expect } from "vitest";
import {
  cmdAgentStatus,
  formatAgentStatusLine,
} from "./agent-status.js";
import type { AgentStatusBody } from "../agent/protocol.js";

describe("formatAgentStatusLine", () => {
  it("formats unlocked / locked / not_running with socket source", () => {
    expect(
      formatAgentStatusLine(
        "unlocked",
        { locked: false, idleRemainingMs: 1500, maxAgeRemainingMs: 90000 },
        "/run/user/1000/abra/agent.sock",
        "run-user-fallback",
        "XDG_RUNTIME_DIR unset",
      ),
    ).toBe(
      "abra-agent: unlocked (idle 2s left, max-age 90s left; socket /run/user/1000/abra/agent.sock via /run/user/<uid> fallback: XDG_RUNTIME_DIR unset)",
    );
    expect(
      formatAgentStatusLine(
        "locked",
        { locked: true, idleRemainingMs: null, maxAgeRemainingMs: null },
        "/run/user/1000/abra/agent.sock",
        "run-user-fallback",
        "XDG_RUNTIME_DIR unset",
      ),
    ).toBe(
      "abra-agent: locked (socket /run/user/1000/abra/agent.sock via /run/user/<uid> fallback: XDG_RUNTIME_DIR unset)",
    );
    expect(
      formatAgentStatusLine(
        "not_running",
        null,
        "/tmp/missing.sock",
        "XDG_RUNTIME_DIR",
        "XDG_RUNTIME_DIR set",
      ),
    ).toBe(
      "abra-agent: not running (socket /tmp/missing.sock via XDG_RUNTIME_DIR: XDG_RUNTIME_DIR set)",
    );
  });
});

describe("cmdAgentStatus", () => {
  const unlocked: AgentStatusBody = {
    locked: false,
    idleRemainingMs: 14_000,
    maxAgeRemainingMs: 28_000_000,
  };
  const locked: AgentStatusBody = {
    locked: true,
    idleRemainingMs: null,
    maxAgeRemainingMs: null,
  };

  const baseDeps = {
    resolveSocketPath: () => "/tmp/abra.sock",
    resolveRuntimeBase: () =>
      ({
        source: "XDG_RUNTIME_DIR" as const,
        reason: "XDG_RUNTIME_DIR set",
      }),
    existsSync: () => true,
  };

  it("unlocked → exit 0", async () => {
    const logs: string[] = [];
    let code: number | undefined;
    await cmdAgentStatus(
      {},
      {
        ...baseDeps,
        status: async () => unlocked,
        log: (m) => logs.push(m),
        exit: (c) => {
          code = c;
        },
      },
    );
    expect(code).toBe(0);
    expect(logs[0]).toMatch(/^abra-agent: unlocked/);
    expect(logs[0]).toContain("via XDG_RUNTIME_DIR");
  });

  it("locked → exit 1 with socket annotation", async () => {
    const logs: string[] = [];
    let code: number | undefined;
    await cmdAgentStatus(
      {},
      {
        ...baseDeps,
        status: async () => locked,
        resolveSocketPath: () => "/run/user/1000/abra/agent.sock",
        resolveRuntimeBase: () => ({
          source: "run-user-fallback",
          reason: "XDG_RUNTIME_DIR unset",
        }),
        log: (m) => logs.push(m),
        exit: (c) => {
          code = c;
        },
      },
    );
    expect(code).toBe(1);
    expect(logs[0]).toBe(
      "abra-agent: locked (socket /run/user/1000/abra/agent.sock via /run/user/<uid> fallback: XDG_RUNTIME_DIR unset)",
    );
  });

  it("not running → exit 2", async () => {
    const logs: string[] = [];
    let code: number | undefined;
    await cmdAgentStatus(
      {},
      {
        ...baseDeps,
        resolveSocketPath: () => "/tmp/missing.sock",
        existsSync: () => false,
        log: (m) => logs.push(m),
        exit: (c) => {
          code = c;
        },
      },
    );
    expect(code).toBe(2);
    expect(logs[0]).toContain("not running");
    expect(logs[0]).toContain("via XDG_RUNTIME_DIR");
  });

  it("--json prints state + socketSource/socketReason", async () => {
    const logs: string[] = [];
    await cmdAgentStatus(
      { json: true },
      {
        ...baseDeps,
        status: async () => unlocked,
        resolveRuntimeBase: () => ({
          source: "run-user-fallback",
          reason: "XDG_RUNTIME_DIR unset",
        }),
        log: (m) => logs.push(m),
        exit: () => {},
      },
    );
    const body = JSON.parse(logs[0]!);
    expect(body.state).toBe("unlocked");
    expect(body.locked).toBe(false);
    expect(body.idleRemainingMs).toBe(14_000);
    expect(body.socketSource).toBe("run-user-fallback");
    expect(body.socketReason).toBe("XDG_RUNTIME_DIR unset");
    expect(JSON.stringify(body)).not.toMatch(/[A-Za-z0-9+/]{40,}={0,2}/);
  });

  it("--wait succeeds after N polls", async () => {
    let polls = 0;
    let code: number | undefined;
    let t = 0;
    await cmdAgentStatus(
      { wait: true, timeout: 10 },
      {
        ...baseDeps,
        status: async () => {
          polls++;
          return polls >= 3 ? unlocked : locked;
        },
        sleep: async () => {
          t += 1000;
        },
        now: () => t,
        log: () => {},
        exit: (c) => {
          code = c;
        },
      },
    );
    expect(polls).toBe(3);
    expect(code).toBe(0);
  });

  it("--wait timeout → exit 1", async () => {
    let code: number | undefined;
    let t = 0;
    await cmdAgentStatus(
      { wait: true, timeout: 2 },
      {
        ...baseDeps,
        status: async () => locked,
        sleep: async () => {
          t += 1000;
        },
        now: () => t,
        log: () => {},
        exit: (c) => {
          code = c;
        },
      },
    );
    expect(code).toBe(1);
  });
});
