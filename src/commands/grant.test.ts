import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { parseGrantTtl, isInterpreterBasename, cmdGrantAdd, cmdGrantList, cmdGrantRevoke } from "./grant.js";
import { GRANT_TTL_MAX_SECONDS } from "../agent/grants.js";

vi.mock("../platform/index.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../platform/index.js")>();
  return {
    ...actual,
    authenticate: vi.fn(async () => undefined),
    resolveAuthBackend: vi.fn(() => "passphrase"),
  };
});

vi.mock("../core/vault.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../core/vault.js")>();
  return {
    ...actual,
    loadVault: vi.fn(async () => ({
      version: 1,
      projects: {
        demo: { createdAt: 1, vars: {} },
      },
      connections: {},
      apiKeys: {},
    })),
  };
});

vi.mock("../agent/index.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../agent/index.js")>();
  return {
    ...actual,
    shouldTryAgent: vi.fn(() => true),
    // Overridden per test with a path inside the test's temp dir.
    resolveAgentSocketPath: vi.fn(() => ""),
    agentStatus: vi.fn(async () => ({
      locked: false,
      idleRemainingMs: 1000,
      maxAgeRemainingMs: 1000,
    })),
    agentGrantAdd: vi.fn(async ({ project, caller, ttlSeconds }) => ({
      id: "deadbeef",
      project,
      caller,
      createdAt: Date.now(),
      expiresAt: Date.now() + ttlSeconds * 1000,
    })),
    agentGrantList: vi.fn(async () => [
      {
        id: "deadbeef",
        project: "demo",
        caller: { exe: "/bin/client" },
        remainingMs: 60_000,
      },
    ]),
    agentGrantRevoke: vi.fn(async () => 1),
  };
});

const platform = await import("../platform/index.js");
const agent = await import("../agent/index.js");

describe("parseGrantTtl", () => {
  it("parses units and plain seconds", () => {
    expect(parseGrantTtl("90s")).toBe(90);
    expect(parseGrantTtl("30m")).toBe(1800);
    expect(parseGrantTtl("2h")).toBe(7200);
    expect(parseGrantTtl("8h")).toBe(28800);
    expect(parseGrantTtl("120")).toBe(120);
  });

  it("rejects below min and above max", () => {
    expect(() => parseGrantTtl("30s")).toThrow(/at least/);
    expect(() => parseGrantTtl("9h")).toThrow(/at most/);
    expect(() => parseGrantTtl(String(GRANT_TTL_MAX_SECONDS + 1))).toThrow(/at most/);
  });
});

describe("isInterpreterBasename", () => {
  it("flags interpreters and python3.x", () => {
    expect(isInterpreterBasename("node")).toBe(true);
    expect(isInterpreterBasename("python3.12")).toBe(true);
    expect(isInterpreterBasename("bash")).toBe(true);
    expect(isInterpreterBasename("my-mcp-client")).toBe(false);
  });
});

// Grants are Linux/unix-only (abra-agent unix socket; exec bits) — same as agent tests.
describe.skipIf(process.platform === "win32")("cmdGrant CLI", () => {
  let tmp = "";
  let exePath = "";

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "abra-grant-cli-"));
    exePath = path.join(tmp, "client-bin");
    fs.writeFileSync(exePath, "#!/bin/sh\n");
    fs.chmodSync(exePath, 0o755);
    const fakeSock = path.join(tmp, "agent.sock");
    fs.writeFileSync(fakeSock, "");
    vi.mocked(agent.resolveAgentSocketPath).mockReturnValue(fakeSock);
    vi.mocked(platform.authenticate).mockClear();
    vi.mocked(agent.agentGrantAdd).mockClear();
    vi.mocked(agent.agentStatus).mockResolvedValue({
      locked: false,
      idleRemainingMs: 1000,
      maxAgeRemainingMs: 1000,
    });
    vi.mocked(agent.shouldTryAgent).mockReturnValue(true);
  });

  afterEach(() => {
    try {
      fs.rmSync(tmp, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  it("refuses interpreters unless --allow-interpreter", async () => {
    const nodePath = path.join(tmp, "node");
    fs.writeFileSync(nodePath, "x");
    fs.chmodSync(nodePath, 0o755);
    await expect(
      cmdGrantAdd({ project: "demo", caller: nodePath, ttl: "2h" }),
    ).rejects.toThrow(/interpreter/);
    await expect(
      cmdGrantAdd({
        project: "demo",
        caller: nodePath,
        ttl: "2h",
        allowInterpreter: true,
      }),
    ).resolves.toBeUndefined();
  });

  it("calls authenticate before grant.add", async () => {
    const order: string[] = [];
    vi.mocked(platform.authenticate).mockImplementation(async () => {
      order.push("auth");
    });
    vi.mocked(agent.agentGrantAdd).mockImplementation(async (args) => {
      order.push("add");
      return {
        id: "abcd1234",
        project: args.project,
        caller: args.caller,
        createdAt: 1,
        expiresAt: 2,
      };
    });
    await cmdGrantAdd({ project: "demo", caller: exePath, ttl: "5m" });
    expect(order).toEqual(["auth", "add"]);
  });

  it("agent locked → clear error", async () => {
    vi.mocked(agent.agentStatus).mockResolvedValue({
      locked: true,
      idleRemainingMs: null,
      maxAgeRemainingMs: null,
    });
    await expect(
      cmdGrantAdd({ project: "demo", caller: exePath, ttl: "5m" }),
    ).rejects.toThrow(/abra unlock/);
  });

  it("list/revoke output contains no secrets", async () => {
    const logs: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...a) => {
      logs.push(a.map(String).join(" "));
    });
    await cmdGrantList();
    await cmdGrantRevoke("deadbeef");
    spy.mockRestore();
    const joined = logs.join("\n");
    expect(joined).toContain("deadbeef");
    expect(joined).not.toMatch(/abra_[A-Za-z0-9]+/);
    expect(joined).not.toMatch(/sk-|secret|password/i);
  });
});
