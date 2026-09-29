import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";
import crypto from "node:crypto";
import http from "node:http";
import { createApiServer } from "./server.js";
import { emptyVault } from "../core/vault.js";
import { generateApiKey } from "../core/apikeys.js";
import { clearTokenCache } from "../core/github-app.js";

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

const vaultModule = (await import("../core/vault.js")) as typeof import("../core/vault.js") & {
  __setVault: (v: ReturnType<typeof emptyVault>) => void;
};

const pem = crypto
  .generateKeyPairSync("rsa", { modulusLength: 2048 })
  .privateKey.export({ type: "pkcs1", format: "pem" })
  .toString();

function makeVault({ connected = true, grant = true } = {}) {
  const vault = emptyVault();
  const granted = generateApiKey("vm", ["gotchibot"]);
  const plain = generateApiKey("plain", ["gotchibot"]);
  if (grant) {
    granted.record.github = { repositories: ["gotchibot"], permissions: { contents: "write", pull_requests: "write" } };
  }
  vault.apiKeys = { [granted.record.id]: granted.record, [plain.record.id]: plain.record };
  if (connected) {
    const v = (value: string, secret = false) => ({ value, secret, updatedAt: 1 });
    vault.connections = {
      github: {
        provider: "github",
        createdAt: 1,
        meta: {},
        vars: {
          GITHUB_APP_ID: v("12345"),
          GITHUB_APP_INSTALLATION_ID: v("678"),
          GITHUB_APP_PRIVATE_KEY: v(pem, true),
        },
      },
    };
  }
  return { vault, grantedKey: granted.fullKey, plainKey: plain.fullKey };
}

async function post(server: http.Server, body: unknown, key?: string) {
  const port = (server.address() as { port: number }).port;
  const res = await fetch(`http://127.0.0.1:${port}/github/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(key ? { Authorization: `Bearer ${key}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe("POST /github/token", () => {
  let server: http.Server;
  let github: http.Server;
  let githubStatus = 201;

  beforeAll(async () => {
    github = http.createServer((req, res) => {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", () => {
        const body = raw ? JSON.parse(raw) : {};
        res.writeHead(githubStatus, { "content-type": "application/json" });
        res.end(
          githubStatus === 201
            ? JSON.stringify({
                token: "ghs_minted",
                expires_at: new Date(Date.now() + 3_600_000).toISOString(),
                repositories: body.repositories.map((name: string) => ({ name })),
                permissions: body.permissions,
              })
            : JSON.stringify({ message: "Bad credentials" }),
        );
      });
    });
    await new Promise<void>((r) => github.listen(0, "127.0.0.1", () => r()));
    process.env.ABRA_GITHUB_API_BASE = `http://127.0.0.1:${(github.address() as { port: number }).port}`;
    server = createApiServer();
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  });

  afterAll(async () => {
    delete process.env.ABRA_GITHUB_API_BASE;
    await new Promise<void>((r) => server.close(() => r()));
    await new Promise<void>((r) => github.close(() => r()));
  });

  beforeEach(() => {
    githubStatus = 201;
    clearTokenCache();
  });

  it("mints a token limited to the key's grant", async () => {
    const { vault, grantedKey } = makeVault();
    vaultModule.__setVault(vault);
    const res = await post(server, undefined, grantedKey);
    expect(res.status).toBe(200);
    expect(res.body.token).toBe("ghs_minted");
    expect(res.body.repositories).toEqual(["gotchibot"]);
    expect(res.body.permissions).toEqual({ contents: "write", pull_requests: "write" });
  });

  it("requires an API key", async () => {
    vaultModule.__setVault(makeVault().vault);
    expect((await post(server, {})).status).toBe(401);
    expect((await post(server, {}, "abra_deadbeef_nope")).status).toBe(401);
  });

  it("refuses keys without a GitHub grant", async () => {
    const { vault, plainKey } = makeVault();
    vaultModule.__setVault(vault);
    const res = await post(server, {}, plainKey);
    expect(res.status).toBe(403);
    expect(String(res.body.error)).toMatch(/no GitHub grant/);
  });

  it("refuses requests outside the grant", async () => {
    const { vault, grantedKey } = makeVault();
    vaultModule.__setVault(vault);
    const res = await post(server, { repositories: ["aarcadegh-t"] }, grantedKey);
    expect(res.status).toBe(403);
    expect(String(res.body.error)).toMatch(/not granted: aarcadegh-t/);
  });

  it("503s when no GitHub App is connected", async () => {
    const { vault, grantedKey } = makeVault({ connected: false });
    vaultModule.__setVault(vault);
    expect((await post(server, {}, grantedKey)).status).toBe(503);
  });

  it("502s with GitHub's message when GitHub refuses", async () => {
    githubStatus = 401;
    const { vault, grantedKey } = makeVault();
    vaultModule.__setVault(vault);
    const res = await post(server, {}, grantedKey);
    expect(res.status).toBe(502);
    expect(String(res.body.error)).toMatch(/Bad credentials/);
  });
});
