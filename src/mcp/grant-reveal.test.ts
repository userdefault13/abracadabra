import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { emptyVault } from "../core/vault.js";
import { NoTtyApprovalError } from "../platform/auth-passphrase.js";
import { issueMcpGrant, revokeAllMcpGrants } from "./grants.js";

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

vi.mock("../platform/index.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../platform/index.js")>();
  return {
    ...actual,
    authenticate: vi.fn(),
    resolveAuthBackend: vi.fn(() => "passphrase"),
  };
});

vi.mock("../platform/reveal-gate.js", () => ({
  authorizeReveal: vi.fn(),
}));

vi.mock("../core/caller-identity.js", () => ({
  identifyMcpCaller: vi.fn(async () => ({
    exe: "/usr/bin/mcp-client",
    dev: 1,
    ino: 99,
  })),
}));

vi.mock("../commands/safe.js", () => ({
  getSafeStatus: vi.fn(),
  payFromSafe: vi.fn(async () => {
    throw new NoTtyApprovalError();
  }),
  listPendingSafeTxs: vi.fn(),
}));

const vaultMod = (await import("../core/vault.js")) as typeof import("../core/vault.js") & {
  __setVault: (v: ReturnType<typeof emptyVault>) => void;
};
const revealGate = await import("../platform/reveal-gate.js");
const platform = await import("../platform/index.js");
const { getSecrets, requestSafePayment } = await import("./server.js");

function seedVault() {
  const vault = emptyVault();
  vault.projects.demo = {
    createdAt: 1,
    vars: { TOKEN: { value: "tok_secret", secret: true, updatedAt: 1 } },
  };
  vaultMod.__setVault(vault);
}

describe("MCP getSecrets + grant gate", () => {
  beforeEach(() => {
    seedVault();
    revokeAllMcpGrants();
    vi.mocked(platform.resolveAuthBackend).mockReturnValue("passphrase");
    vi.mocked(revealGate.authorizeReveal).mockReset();
  });

  afterEach(() => {
    revokeAllMcpGrants();
  });

  it("headless no grant → approved:false with hint", async () => {
    vi.mocked(revealGate.authorizeReveal).mockRejectedValue(
      new Error(
        'abracadabra: approval denied — no terminal and no matching grant for this caller. Run on a terminal: abra grant --project demo --caller /usr/bin/mcp-client --ttl <≤8h>',
      ),
    );
    const res = await getSecrets({ project: "demo", keys: ["TOKEN"] });
    expect(res.isError).toBe(true);
    const body = JSON.parse(res.content[0].text);
    expect(body.approved).toBe(false);
    expect(body.error).toMatch(/abra grant/);
  });

  it("matching grant → vars with grantedVia abra-grant", async () => {
    vi.mocked(revealGate.authorizeReveal).mockResolvedValue({
      via: "grant",
      grantId: "abcd1234",
    });
    const res = await getSecrets({ project: "demo", keys: ["TOKEN"] });
    expect(res.isError).toBeFalsy();
    const body = JSON.parse(res.content[0].text);
    expect(body.approved).toBe(true);
    expect(body.grantedVia).toBe("abra-grant");
    expect(body.vars.TOKEN).toBe("tok_secret");
  });

  it("requestedBy spoofing does not matter (caller from identifyMcpCaller)", async () => {
    vi.mocked(revealGate.authorizeReveal).mockResolvedValue({ via: "grant", grantId: "x" });
    await getSecrets({
      project: "demo",
      keys: ["TOKEN"],
      requestedBy: "totally-legit-spoof",
    });
    const call = vi.mocked(revealGate.authorizeReveal).mock.calls[0][0];
    expect(call.project).toBe("demo");
    // caller is a function — not requestedBy
    expect(typeof call.caller).toBe("function");
  });

  it("passphrase backend ignores ttl session grants", async () => {
    issueMcpGrant("spoof-agent", "demo", 600);
    vi.mocked(revealGate.authorizeReveal).mockRejectedValue(
      new Error("abra grant required"),
    );
    const res = await getSecrets({
      project: "demo",
      keys: ["TOKEN"],
      ttl: 600,
      requestedBy: "spoof-agent",
    });
    const body = JSON.parse(res.content[0].text);
    expect(body.approved).toBe(false);
    expect(revealGate.authorizeReveal).toHaveBeenCalled();
  });

  it("request_safe_payment with no TTY stays denied (does not use grant)", async () => {
    const res = await requestSafePayment({
      to: "0x0000000000000000000000000000000000000001",
      amountUsdc: "0.01",
      reason: "test",
    });
    const body = JSON.parse(res.content[0].text);
    expect(body.approved).toBe(false);
    // reveal-gate was not consulted for payment
    expect(revealGate.authorizeReveal).not.toHaveBeenCalled();
  });
});

describe("payments do not import reveal-gate", () => {
  it("safe/treasury/keygen source scan", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
    for (const rel of ["commands/safe.ts", "commands/treasury.ts", "commands/keygen.ts"]) {
      const src = fs.readFileSync(path.join(root, rel), "utf8");
      expect(src).not.toMatch(/reveal-gate/);
      expect(src).not.toMatch(/authorizeReveal/);
    }
  });
});
