import { describe, expect, it } from "vitest";
import { buildVercelEnvBody, parseTargets, resolveVercelTarget } from "./push.js";

const entry = (value: string, secret: boolean) => ({ value, secret, updatedAt: 0 });

describe("parseTargets", () => {
  it("defaults to production + preview", () => {
    expect(parseTargets(undefined)).toEqual(["production", "preview"]);
  });

  it("normalises, de-duplicates and validates", () => {
    expect(parseTargets(" Production, preview ,production")).toEqual(["production", "preview"]);
    expect(() => parseTargets("staging")).toThrow(/Unknown Vercel target "staging"/);
    expect(() => parseTargets(" , ")).toThrow(/at least one target/);
  });
});

describe("resolveVercelTarget", () => {
  const conn = {
    vars: {
      VERCEL_TOKEN: entry("tok", true),
      VERCEL_PROJECT_ID: entry("prj_conn", false),
      VERCEL_ORG_ID: entry("team_conn", false),
    },
  };

  it("prefers the explicit flag, then the linked directory, then the connection", () => {
    expect(
      resolveVercelTarget({ flagProject: "my-app", link: { projectId: "prj_link" }, conn }),
    ).toMatchObject({ project: "my-app", source: "flag" });
    expect(resolveVercelTarget({ link: { projectId: "prj_link" }, conn })).toMatchObject({
      project: "prj_link",
      source: "link",
    });
    expect(resolveVercelTarget({ link: null, conn })).toMatchObject({
      project: "prj_conn",
      teamId: "team_conn",
      source: "connection",
    });
  });

  it("drops personal-scope org ids that are not teams", () => {
    expect(
      resolveVercelTarget({ link: { projectId: "prj_link", orgId: "user_123" }, conn: { vars: {} } }).teamId,
    ).toBeUndefined();
    expect(
      resolveVercelTarget({ link: { projectId: "prj_link", orgId: "team_abc" }, conn: { vars: {} } }).teamId,
    ).toBe("team_abc");
  });

  it("fails clearly when no project can be resolved", () => {
    expect(() => resolveVercelTarget({ link: null, conn: { vars: {} } })).toThrow(/No Vercel project/);
  });
});

describe("buildVercelEnvBody", () => {
  it("encrypts secrets and leaves plain vars readable", () => {
    expect(buildVercelEnvBody("API_KEY", entry("v", true), ["production"])).toEqual({
      key: "API_KEY",
      value: "v",
      type: "encrypted",
      target: ["production"],
    });
    expect(buildVercelEnvBody("PUBLIC_URL", entry("u", false), ["preview", "production"]).type).toBe("plain");
  });
});

import { parseKeyMapping, parseSshTarget, remoteUpsertScript } from "./push.js";

describe("push ssh helpers", () => {
  it("maps KEY and LOCAL:REMOTE specs", () => {
    expect(parseKeyMapping("EVM_PRIVATE_KEY")).toEqual({ local: "EVM_PRIVATE_KEY", remote: "EVM_PRIVATE_KEY" });
    expect(parseKeyMapping("EVM_PRIVATE_KEY:ACARTRIDGE_ATTESTOR_PRIVATE_KEY")).toEqual({
      local: "EVM_PRIVATE_KEY",
      remote: "ACARTRIDGE_ATTESTOR_PRIVATE_KEY",
    });
    expect(() => parseKeyMapping("bad-name")).toThrow(/Invalid env var name/);
  });

  it("parses ssh targets strictly", () => {
    expect(parseSshTarget("root@1.2.3.4")).toEqual({ user: "root", host: "1.2.3.4", port: undefined });
    expect(parseSshTarget("deploy@realm.example.com:2222")).toMatchObject({ port: 2222 });
    expect(() => parseSshTarget("-oProxyCommand=x@host")).toThrow(/Bad ssh target/);
    expect(() => parseSshTarget("root@host bad")).toThrow(/Bad ssh target/);
  });

  it("builds a remote upsert script and rejects odd paths", () => {
    const s = remoteUpsertScript("/opt/app/.env");
    expect(s).toContain("f=/opt/app/.env");
    expect(s).toContain("chmod 600");
    expect(() => remoteUpsertScript("/opt/app/.env; rm -rf /")).toThrow(/Bad remote path/);
  });
});
