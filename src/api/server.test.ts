import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";
import http from "node:http";
import { createApiServer } from "./server.js";
import { emptyVault } from "../core/vault.js";
import { generateApiKey } from "../core/apikeys.js";
import { revokeAll } from "./grants.js";

vi.mock("../core/vault.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../core/vault.js")>();
  let vault = actual.emptyVault();
  return {
    ...actual,
    loadVault: vi.fn(async () => vault),
    saveVault: vi.fn(async (v: typeof vault) => {
      vault = v;
    }),
    __setVault(v: typeof vault) {
      vault = v;
    },
  };
});

vi.mock("./identify.js", () => ({
  identifyPeer: vi.fn(async () => ({
    appId: "test-client",
    display: "test-client (pid 1)",
  })),
}));

const vaultModule = await import("../core/vault.js") as typeof import("../core/vault.js") & {
  __setVault: (v: ReturnType<typeof emptyVault>) => void;
};

function makeVault() {
  const vault = emptyVault();
  vault.projects.demo = {
    createdAt: Date.now(),
    vars: {
      TOKEN: { value: "tok_secret", secret: true, updatedAt: 1 },
      PUBLIC: { value: "visible", secret: false, updatedAt: 1 },
    },
  };
  const { record, fullKey } = generateApiKey("test-key", ["demo"]);
  vault.apiKeys = { [record.id]: record };
  return { vault, fullKey, record };
}

async function request(
  server: http.Server,
  method: string,
  path: string,
  body?: unknown,
  headers?: Record<string, string>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const port = (server.address() as { port: number }).port;
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  return { status: res.status, body: json };
}

describe("POST /secret", () => {
  let server: http.Server;

  beforeAll(async () => {
    process.env.ABRA_SKIP_BIOMETRICS = "1";
    server = createApiServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
  });

  beforeEach(() => {
    revokeAll();
    const { vault } = makeVault();
    vaultModule.__setVault(vault);
  });

  it("serves secrets with a valid API key", async () => {
    const { vault, fullKey } = makeVault();
    vaultModule.__setVault(vault);

    const { status, body } = await request(
      server,
      "POST",
      "/secret",
      { project: "demo", keys: ["TOKEN"] },
      { Authorization: `Bearer ${fullKey}` },
    );

    expect(status).toBe(200);
    expect(body.TOKEN).toBe("tok_secret");
  });

  it("returns 401 for invalid API key", async () => {
    const { status, body } = await request(
      server,
      "POST",
      "/secret",
      { project: "demo", keys: ["TOKEN"] },
      { Authorization: "Bearer abra_deadbeef_invalid" },
    );

    expect(status).toBe(401);
    expect(body.error).toMatch(/invalid/i);
  });

  it("returns 403 when key lacks project scope", async () => {
    const vault = emptyVault();
    const { record, fullKey } = generateApiKey("other", ["other-proj"]);
    vault.apiKeys = { [record.id]: record };
    vault.projects.demo = {
      createdAt: Date.now(),
      vars: { TOKEN: { value: "x", secret: true, updatedAt: 1 } },
    };
    vaultModule.__setVault(vault);

    const { status } = await request(
      server,
      "POST",
      "/secret",
      { project: "demo", keys: ["TOKEN"] },
      { Authorization: `Bearer ${fullKey}` },
    );

    expect(status).toBe(403);
  });

  it("returns 404 for unknown project", async () => {
    const { vault, fullKey } = makeVault();
    vaultModule.__setVault(vault);

    const { status } = await request(
      server,
      "POST",
      "/secret",
      { project: "missing", keys: ["TOKEN"] },
      { Authorization: `Bearer ${fullKey}` },
    );

    expect(status).toBe(404);
  });

  it("serves via biometric path when no bearer token", async () => {
    const { status, body } = await request(server, "POST", "/secret", {
      project: "demo",
      keys: ["PUBLIC"],
    });

    expect(status).toBe(200);
    expect(body.PUBLIC).toBe("visible");
  });
});
