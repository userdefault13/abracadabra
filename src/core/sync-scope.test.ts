import { describe, it, expect, vi } from "vitest";
import {
  TREASURY_PROJECT,
  type Vault,
  type Project,
} from "./vault.js";
import {
  sealScopedBundle,
  openAnyBundle,
  openBundle,
  ScopedBundleError,
} from "./backup.js";
import {
  assertScopeNamesAllowed,
  validateScope,
  extractScopedProjects,
  mergeScopedProjects,
  formatScopedReport,
} from "./sync-scope.js";
import { fingerprintsMatch, createEphemeralTls } from "./tls-ephemeral.js";

const skipWin = process.platform === "win32";

function entry(value: string, secret = true, updatedAt = 1) {
  return { value, secret, updatedAt };
}

function makeVault(projects: Record<string, Project>, extra?: Partial<Vault>): Vault {
  return {
    version: 1,
    projects,
    connections: extra?.connections ?? {
      github: {
        provider: "github",
        createdAt: 1,
        meta: {},
        vars: { TOKEN: entry("conn-secret") },
      },
    },
    passkeys: extra?.passkeys ?? [],
    apiKeys: extra?.apiKeys ?? {
      k1: {
        id: "k1",
        name: "agent",
        keyHash: "abc",
        prefix: "abra_",
        projects: null,
        createdAt: 1,
      },
    },
  };
}

describe("sync-scope", () => {
  it("assertScopeNamesAllowed refuses treasury and reserved", () => {
    expect(() => assertScopeNamesAllowed([TREASURY_PROJECT])).toThrow(/refused/);
    expect(() => assertScopeNamesAllowed(["__abra_other"])).toThrow(/refused/);
    expect(() => assertScopeNamesAllowed([])).toThrow(/at least one/);
  });

  it("validateScope lists all unknown names", () => {
    const vault = makeVault({
      a: { createdAt: 1, vars: { K: entry("1") } },
    });
    expect(() => validateScope(vault, ["a", "missing", "gone"])).toThrow(
      /unknown project\(s\): missing, gone/,
    );
    expect(validateScope(vault, [" a ", "a"])).toEqual(["a"]);
  });

  it("extractScopedProjects deep-copies only named projects", () => {
    const vault = makeVault({
      a: { createdAt: 1, vars: { K: entry("1") } },
      b: { createdAt: 1, vars: { K: entry("2") } },
    });
    const extracted = extractScopedProjects(vault, ["a"]);
    expect(Object.keys(extracted)).toEqual(["a"]);
    extracted.a.vars.K.value = "mutated";
    expect(vault.projects.a.vars.K.value).toBe("1");
  });

  it("mergeScopedProjects never deletes; keeps receiver on conflict; --theirs takes host", () => {
    const local = makeVault({
      keep: { createdAt: 1, vars: { LOCAL_ONLY: entry("stay") } },
      shared: {
        createdAt: 1,
        vars: {
          SAME: entry("same", true, 1),
          CONFLICT: entry("local-val", true, 1),
          LOCAL_KEY: entry("only-here"),
        },
      },
    });
    const incoming: Record<string, Project> = {
      shared: {
        createdAt: 99,
        vars: {
          SAME: entry("same", true, 99),
          CONFLICT: entry("host-val", true, 99),
          NEW: entry("from-host"),
        },
      },
      brandnew: { createdAt: 2, vars: { A: entry("1"), B: entry("2"), C: entry("3") } },
    };

    const def = mergeScopedProjects(local, incoming, {});
    expect(def.merged.projects.keep.vars.LOCAL_ONLY.value).toBe("stay");
    expect(def.merged.projects.shared.vars.LOCAL_KEY.value).toBe("only-here");
    expect(def.merged.projects.shared.vars.CONFLICT.value).toBe("local-val");
    expect(def.merged.projects.shared.vars.NEW.value).toBe("from-host");
    expect(def.merged.projects.brandnew).toBeDefined();
    expect(def.merged.connections?.github).toBeDefined();
    expect(def.merged.apiKeys?.k1).toBeDefined();
    expect(def.report.conflicts).toEqual([{ project: "shared", key: "CONFLICT" }]);
    expect(def.report.added).toEqual([{ project: "shared", key: "NEW" }]);
    expect(def.report.newProjects).toEqual([{ project: "brandnew", keys: 3 }]);
    expect(local.projects.shared.vars.NEW).toBeUndefined(); // no mutate

    const theirs = mergeScopedProjects(local, incoming, { theirs: true });
    expect(theirs.merged.projects.shared.vars.CONFLICT.value).toBe("host-val");
    expect(theirs.report.conflicts).toHaveLength(0);
    expect(theirs.report.changed).toEqual([{ project: "shared", key: "CONFLICT" }]);
  });

  it("formatScopedReport prints names only", () => {
    const lines = formatScopedReport({
      newProjects: [{ project: "gotchibot", keys: 3 }],
      added: [{ project: "gotchibot", key: "KEY" }],
      changed: [{ project: "gotchibot", key: "OTHER" }],
      conflicts: [{ project: "gotchibot", key: "CONFLICT" }],
    });
    expect(lines).toEqual([
      "+ project gotchibot (new, 3 keys)",
      "+ gotchibot/KEY added",
      "~ gotchibot/OTHER taken from host (--theirs)",
      "! gotchibot/CONFLICT conflict — kept this machine's value (use --theirs to take the host's)",
    ]);
    expect(lines.join("\n")).not.toMatch(/secret-value|••••/);
    // report mentions the word "value" in conflict guidance — never secret contents
    expect(lines.join("\n")).not.toContain("gotchibot's");
  });
});

describe("scoped backup payload", () => {
  it("sealScopedBundle has only projects — openBundle throws ScopedBundleError", () => {
    const projects = {
      gotchibot: { createdAt: 1, vars: { K: entry("secret-value-xyz") } },
    };
    const bundle = sealScopedBundle(projects, ["gotchibot"], "pin-passphrase");
    expect(bundle.format).toBe("abracadabra-backup");
    expect(bundle.kind).toBe("scoped-projects");

    expect(() => openBundle(bundle, "pin-passphrase")).toThrow(ScopedBundleError);

    const opened = openAnyBundle(bundle, "pin-passphrase");
    expect(opened.kind).toBe("scoped");
    if (opened.kind !== "scoped") return;
    expect(opened.payload.kind).toBe("scoped-projects");
    expect(opened.payload.scope).toEqual(["gotchibot"]);
    expect(Object.keys(opened.payload.projects)).toEqual(["gotchibot"]);
    expect(opened.payload).not.toHaveProperty("masterKey");
    expect(opened.payload).not.toHaveProperty("vaultEnc");
    expect(opened.payload).not.toHaveProperty("connections");
    expect(opened.payload).not.toHaveProperty("passkeys");
    expect(opened.payload).not.toHaveProperty("apiKeys");
    expect(JSON.stringify(opened.payload)).not.toContain("__abra_treasury__");
  });
});

describe("fingerprintsMatch", () => {
  it("exact full match; legacy 16-hex with warning; other lengths false", () => {
    const full = "AA".repeat(32);
    const colon = (full.match(/.{2}/g) ?? []).join(":");
    expect(fingerprintsMatch(colon, colon)).toBe(true);
    expect(fingerprintsMatch(full, colon)).toBe(true);

    const warn = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(fingerprintsMatch(full.slice(0, 16), colon)).toBe(true);
    expect(warn).toHaveBeenCalledWith(
      expect.stringMatching(/legacy short TLS fingerprint/i),
    );
    warn.mockRestore();

    expect(fingerprintsMatch("aabbccdd", colon)).toBe(false); // 8 hex
    expect(fingerprintsMatch("00".repeat(32), colon)).toBe(false);
  });

  it.runIf(!skipWin)("createEphemeralTls returns full 32-pair fingerprint", () => {
    const tls = createEphemeralTls("fp-len");
    const hex = tls.fingerprint.replace(/[^0-9A-Fa-f]/g, "");
    expect(hex).toHaveLength(64);
    expect(tls.fingerprint.split(":")).toHaveLength(32);
  });
});
