import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, afterEach } from "vitest";
import { agentRequest, AgentClientError } from "./client.js";
import { PROTOCOL_VERSION } from "./protocol.js";

/**
 * A slow peer check (ss retries under load) must not make the client give up
 * after the 500ms connect timeout on sensitive ops.
 */
describe.skipIf(process.platform === "win32")("agent client read timeout", () => {
  let server: net.Server | null = null;
  let dir = "";

  afterEach(async () => {
    if (server) await new Promise<void>((r) => server!.close(() => r()));
    server = null;
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  async function slowAgent(delayMs: number, body: Record<string, unknown>): Promise<string> {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "abra-ct-"));
    const sock = path.join(dir, "a.sock");
    server = net.createServer((s) => {
      s.on("data", (chunk) => {
        const req = JSON.parse(chunk.toString("utf8").trim()) as { id: string };
        setTimeout(() => {
          s.write(JSON.stringify({ v: PROTOCOL_VERSION, id: req.id, ...body }) + "\n");
        }, delayMs);
      });
      s.on("error", () => {});
    });
    await new Promise<void>((r) => server!.listen(sock, () => r()));
    return sock;
  }

  it("sensitive op waits past connectTimeoutMs and surfaces reason + hint", async () => {
    const socketPath = await slowAgent(400, {
      ok: false,
      code: "forbidden_peer",
      error: "Peer is not the abra CLI",
      reason: "ss_failed:timeout",
      hint: "ss timed out (system load?) — retry: abra unlock",
    });
    const res = await agentRequest(
      { op: "vault.load" },
      { socketPath, connectTimeoutMs: 100 },
    );
    expect(res).toMatchObject({ ok: false, reason: "ss_failed:timeout" });
  });

  it("non-sensitive op keeps the short timeout", async () => {
    const socketPath = await slowAgent(400, {
      ok: true,
      op: "status",
      status: { locked: true, idleRemainingMs: null, maxAgeRemainingMs: null },
    });
    await expect(
      agentRequest({ op: "status" }, { socketPath, connectTimeoutMs: 100 }),
    ).rejects.toMatchObject({ code: "timeout" });
  });

  it("explicit readTimeoutMs wins", async () => {
    const socketPath = await slowAgent(400, { ok: true, op: "vault.save" });
    const err = await agentRequest(
      { op: "vault.save", vault: {} as never },
      { socketPath, connectTimeoutMs: 100, readTimeoutMs: 100 },
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AgentClientError);
    expect((err as AgentClientError).code).toBe("timeout");
  });
});
