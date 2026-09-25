import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";
import http from "node:http";
import { emptyVault } from "../core/vault.js";
import { revokeAll } from "./grants.js";

const authorizeReveal = vi.fn();

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
    display: "test-client (pid 4242)",
    pid: 4242,
  })),
}));

vi.mock("../core/caller-identity.js", () => ({
  identityForPid: vi.fn(async (pid: number) =>
    pid === 4242
      ? { exe: "/usr/bin/test-client", dev: 1, ino: 7 }
      : null,
  ),
}));

vi.mock("../platform/reveal-gate.js", () => ({
  authorizeReveal: (...args: unknown[]) => authorizeReveal(...args),
}));

vi.mock("../platform/index.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../platform/index.js")>();
  return {
    ...actual,
    resolveAuthBackend: vi.fn(() => "passphrase"),
  };
});

const { createApiServer } = await import("./server.js");
const vaultModule = (await import("../core/vault.js")) as typeof import("../core/vault.js") & {
  __setVault: (v: ReturnType<typeof emptyVault>) => void;
};

async function request(
  server: http.Server,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const port = (server.address() as { port: number }).port;
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  return { status: res.status, body: json };
}

describe("POST /secret with abra grant (passphrase)", () => {
  let server: http.Server;

  beforeAll(async () => {
    process.env.ABRA_SKIP_BIOMETRICS = "0";
    process.env.ABRA_AUTH = "passphrase";
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
    authorizeReveal.mockReset();
    const vault = emptyVault();
    vault.projects.demo = {
      createdAt: 1,
      vars: { TOKEN: { value: "tok_secret", secret: true, updatedAt: 1 } },
    };
    vaultModule.__setVault(vault);
  });

  it("matching grant → 200", async () => {
    authorizeReveal.mockResolvedValue({ via: "grant", grantId: "abcd1234" });
    const { status, body } = await request(server, "POST", "/secret", {
      project: "demo",
      keys: ["TOKEN"],
    });
    expect(status).toBe(200);
    expect(body.TOKEN).toBe("tok_secret");
    expect(authorizeReveal).toHaveBeenCalled();
    const args = authorizeReveal.mock.calls[0][0];
    expect(args.project).toBe("demo");
    const identity = await args.caller();
    expect(identity).toEqual({ exe: "/usr/bin/test-client", dev: 1, ino: 7 });
  });

  it("no grant → 403 with abra grant hint", async () => {
    authorizeReveal.mockRejectedValue(
      new Error(
        "abracadabra: approval denied — no terminal and no matching grant for this caller. Run on a terminal: abra grant --project demo --caller /usr/bin/test-client --ttl <≤8h>",
      ),
    );
    const { status, body } = await request(server, "POST", "/secret", {
      project: "demo",
      keys: ["TOKEN"],
    });
    expect(status).toBe(403);
    expect(String(body.error)).toMatch(/abra grant/);
  });
});
