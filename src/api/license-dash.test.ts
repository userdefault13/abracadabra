import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createApiServer } from "./server.js";

vi.mock("../license/verify.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../license/verify.js")>();
  return {
    ...actual,
    fetchNftBalance: vi.fn(async () => 1n),
  };
});

describe("license API", () => {
  const envBackup = { ...process.env };
  let server: http.Server;
  let base = "";
  let tmpHome = "";

  beforeEach(async () => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "abra-api-lic-"));
    process.env.HOME = tmpHome;
    process.env.ABRA_DIR = path.join(tmpHome, ".abracadabra");
    process.env.ABRA_LICENSE_NFT = "0x0000000000000000000000000000000000000001";
    delete process.env.ABRA_SKIP_LICENSE;

    server = createApiServer();
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address();
    if (!addr || typeof addr === "string") throw new Error("no port");
    base = `http://127.0.0.1:${addr.port}`;
  });

  afterEach(async () => {
    process.env = { ...envBackup };
    vi.restoreAllMocks();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it("GET /api/license/status is public", async () => {
    const res = await fetch(`${base}/api/license/status`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.enforcement).toBe(true);
    expect(body.activated).toBe(false);
  });

  it("POST /api/license/activate persists activation", async () => {
    const res = await fetch(`${base}/api/license/activate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ wallet: "0x00000000000000000000000000000000000000aa" }),
    });
    expect(res.status).toBe(200);
    const st = await fetch(`${base}/api/license/status`);
    const status = await st.json();
    expect(status.activated).toBe(true);
    expect(status.wallet).toBe("0x00000000000000000000000000000000000000aa");
  });
});
