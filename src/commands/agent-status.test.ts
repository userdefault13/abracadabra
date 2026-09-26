import { describe, it, expect } from "vitest";
import {
  cmdAgentStatus,
  formatAgentStatusLine,
} from "./agent-status.js";
import type { AgentStatusBody } from "../agent/protocol.js";

describe("formatAgentStatusLine", () => {
  it("formats unlocked / locked / not_running", () => {
    expect(
      formatAgentStatusLine(
        "unlocked",
        { locked: false, idleRemainingMs: 1500, maxAgeRemainingMs: 90000 },
        "/run/abra/agent.sock",
      ),
    ).toBe("abra-agent: unlocked (idle 2s left, max-age 90s left)");
    expect(
      formatAgentStatusLine("locked", { locked: true, idleRemainingMs: null, maxAgeRemainingMs: null }, "/x"),
    ).toBe("abra-agent: locked");
    expect(formatAgentStatusLine("not_running", null, "/tmp/missing.sock")).toBe(
      "abra-agent: not running (/tmp/missing.sock)",
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

  it("unlocked → exit 0", async () => {
    const logs: string[] = [];
    let code: number | undefined;
    await cmdAgentStatus(
      {},
      {
        status: async () => unlocked,
        resolveSocketPath: () => "/tmp/abra.sock",
        existsSync: () => true,
        log: (m) => logs.push(m),
        exit: (c) => {
          code = c;
        },
      },
    );
    expect(code).toBe(0);
    expect(logs[0]).toMatch(/^abra-agent: unlocked/);
  });

  it("locked → exit 1", async () => {
    let code: number | undefined;
    await cmdAgentStatus(
      {},
      {
        status: async () => locked,
        resolveSocketPath: () => "/tmp/abra.sock",
        existsSync: () => true,
        log: () => {},
        exit: (c) => {
          code = c;
        },
      },
    );
    expect(code).toBe(1);
  });

  it("not running → exit 2", async () => {
    const logs: string[] = [];
    let code: number | undefined;
    await cmdAgentStatus(
      {},
      {
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
  });

  it("--json prints state + non-secret fields", async () => {
    const logs: string[] = [];
    await cmdAgentStatus(
      { json: true },
      {
        status: async () => unlocked,
        resolveSocketPath: () => "/tmp/abra.sock",
        existsSync: () => true,
        log: (m) => logs.push(m),
        exit: () => {},
      },
    );
    const body = JSON.parse(logs[0]!);
    expect(body.state).toBe("unlocked");
    expect(body.locked).toBe(false);
    expect(body.idleRemainingMs).toBe(14_000);
    expect(JSON.stringify(body)).not.toMatch(/[A-Za-z0-9+/]{40,}={0,2}/);
  });

  it("--wait succeeds after N polls", async () => {
    let polls = 0;
    let code: number | undefined;
    let t = 0;
    await cmdAgentStatus(
      { wait: true, timeout: 10 },
      {
        status: async () => {
          polls++;
          return polls >= 3 ? unlocked : locked;
        },
        resolveSocketPath: () => "/tmp/abra.sock",
        existsSync: () => true,
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
        status: async () => locked,
        resolveSocketPath: () => "/tmp/abra.sock",
        existsSync: () => true,
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
