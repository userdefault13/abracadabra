import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import crypto from "node:crypto";
import http from "node:http";
import {
  githubAppJwt,
  parseGrant,
  resolveScope,
  mintInstallationToken,
  clearTokenCache,
  GithubScopeError,
} from "./github-app.js";

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = privateKey.export({ type: "pkcs1", format: "pem" }).toString();

describe("githubAppJwt", () => {
  it("is an RS256 JWT GitHub can verify, backdated for skew and under 10 minutes", () => {
    const now = 1_800_000_000_000;
    const jwt = githubAppJwt("12345", pem, now);
    const [h, p, s] = jwt.split(".");
    expect(JSON.parse(Buffer.from(h, "base64url").toString())).toEqual({ alg: "RS256", typ: "JWT" });
    const payload = JSON.parse(Buffer.from(p, "base64url").toString());
    expect(payload.iss).toBe("12345");
    expect(payload.iat).toBe(now / 1000 - 60);
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(600);
    const ok = crypto.createVerify("RSA-SHA256").update(`${h}.${p}`).verify(publicKey, Buffer.from(s, "base64url"));
    expect(ok).toBe(true);
  });
});

describe("parseGrant", () => {
  it("normalizes repo names and parses permissions", () => {
    expect(parseGrant("userdefault13/GotchiBot, AarcadeGh-t,gotchibot", "contents:write,pull_requests:read")).toEqual({
      repositories: ["gotchibot", "aarcadegh-t"],
      permissions: { contents: "write", pull_requests: "read" },
    });
  });

  it("rejects bad levels and empty input", () => {
    expect(() => parseGrant("a", "contents:admin")).toThrow(GithubScopeError);
    expect(() => parseGrant("", "contents:read")).toThrow(GithubScopeError);
    expect(() => parseGrant("a", "")).toThrow(GithubScopeError);
  });
});

describe("resolveScope", () => {
  const grant = { repositories: ["gotchibot", "aarcadegh-t"], permissions: { contents: "write" as const, pull_requests: "read" as const } };

  it("defaults to the whole grant", () => {
    expect(resolveScope(grant)).toEqual({
      repositories: ["aarcadegh-t", "gotchibot"],
      permissions: { contents: "write", pull_requests: "read" },
    });
  });

  it("narrows to a requested subset", () => {
    expect(resolveScope(grant, { repositories: ["GotchiBot"], permissions: { contents: "read" } })).toEqual({
      repositories: ["gotchibot"],
      permissions: { contents: "read" },
    });
  });

  it("refuses anything outside the grant instead of downgrading", () => {
    expect(() => resolveScope(grant, { repositories: ["other"] })).toThrow(/not granted: other/);
    expect(() => resolveScope(grant, { permissions: { pull_requests: "write" } })).toThrow(/pull_requests:write/);
    expect(() => resolveScope(grant, { permissions: { administration: "read" } })).toThrow(/administration/);
    expect(() => resolveScope(grant, { repositories: [] })).toThrow(GithubScopeError);
  });
});

describe("mintInstallationToken", () => {
  let server: http.Server;
  let calls: { url: string; auth: string; body: Record<string, unknown> }[] = [];
  const creds = { appId: "12345", installationId: "678", privateKey: pem };

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", () => {
        const body = raw ? JSON.parse(raw) : {};
        calls.push({ url: req.url ?? "", auth: String(req.headers.authorization ?? ""), body });
        res.writeHead(201, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            token: `ghs_fake_${calls.length}`,
            expires_at: new Date(Date.now() + 3_600_000).toISOString(),
            repositories: (body.repositories ?? []).map((name: string) => ({ name })),
            permissions: body.permissions,
          }),
        );
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    process.env.ABRA_GITHUB_API_BASE = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });

  afterAll(async () => {
    delete process.env.ABRA_GITHUB_API_BASE;
    await new Promise<void>((r) => server.close(() => r()));
  });

  beforeEach(() => {
    calls = [];
    clearTokenCache();
  });

  it("posts the clamped scope to the installation with an app JWT", async () => {
    const minted = await mintInstallationToken(creds, { repositories: ["gotchibot"], permissions: { contents: "write" } });
    expect(minted.token).toBe("ghs_fake_1");
    expect(minted.repositories).toEqual(["gotchibot"]);
    expect(calls[0].url).toBe("/app/installations/678/access_tokens");
    expect(calls[0].auth).toMatch(/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/);
    expect(calls[0].body).toEqual({ repositories: ["gotchibot"], permissions: { contents: "write" } });
  });

  it("reuses a cached token per key and scope", async () => {
    const scope = { repositories: ["gotchibot"], permissions: { contents: "write" as const } };
    const a = await mintInstallationToken(creds, scope, "key1");
    const b = await mintInstallationToken(creds, scope, "key1");
    const c = await mintInstallationToken(creds, scope, "key2");
    expect(b.token).toBe(a.token);
    expect(c.token).not.toBe(a.token);
    expect(calls).toHaveLength(2);
  });
});
