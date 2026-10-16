import { describe, it, expect } from "vitest";
import type { SyncAcceptRule, Vault } from "../core/vault.js";
import {
  decideAccept,
  describeAcceptRule,
  parseProjectsOption,
  removeAcceptRules,
  upsertAcceptRule,
} from "./accept.js";
import { removePeer } from "./peers.js";
import { makePair } from "../../test/fixtures/sync-vaults.js";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";

describe("sync accept policy", () => {
  it("no rules → queue", () => {
    expect(decideAccept(undefined, A, ["app"]).action).toBe("queue");
    expect(decideAccept([], A, ["app"]).action).toBe("queue");
  });

  it("matches by sender (id or *) and by project coverage", () => {
    const rules: SyncAcceptRule[] = [{ from: A, projects: ["app", "web"], auto: true }];
    expect(decideAccept(rules, A, ["app"]).action).toBe("auto");
    expect(decideAccept(rules, A, ["app", "web"]).action).toBe("auto");
    expect(decideAccept(rules, A, ["app", "db"]).action).toBe("queue"); // not fully covered
    expect(decideAccept(rules, B, ["app"]).action).toBe("queue");
    expect(decideAccept([{ from: "*", projects: "*", auto: true }], B, ["anything"]).action).toBe("auto");
  });

  it("an explicit queue rule beats a matching auto rule", () => {
    const rules: SyncAcceptRule[] = [
      { from: "*", projects: "*", auto: true },
      { from: A, projects: ["secrets"], auto: false },
    ];
    expect(decideAccept(rules, A, ["secrets"]).action).toBe("queue");
    expect(decideAccept(rules, A, ["app"]).action).toBe("auto");
    expect(decideAccept(rules, B, ["secrets"]).action).toBe("auto");
  });

  it("upsert replaces the same selector; remove matches it exactly", () => {
    let v: Vault = { version: 1, projects: {} };
    let r = upsertAcceptRule(v, { from: A, projects: ["web", "app"], auto: false });
    expect(r.action).toBe("added");
    r = upsertAcceptRule(r.vault, { from: A, projects: ["app", "web"], auto: true });
    expect(r.action).toBe("updated");
    expect(r.vault.syncAccept).toEqual([{ from: A, projects: ["app", "web"], auto: true }]);
    v = upsertAcceptRule(r.vault, { from: "*", projects: "*", auto: true }).vault;
    expect(v.syncAccept).toHaveLength(2);
    expect(removeAcceptRules(v, { from: A, projects: ["app"] }).removed).toBe(0);
    const rm = removeAcceptRules(v, { from: A, projects: ["web", "app"] });
    expect(rm.removed).toBe(1);
    expect(rm.vault.syncAccept).toEqual([{ from: "*", projects: "*", auto: true }]);
  });

  it("parses -p and refuses reserved names", () => {
    expect(parseProjectsOption(undefined)).toBe("*");
    expect(parseProjectsOption("web, app,app")).toEqual(["app", "web"]);
    expect(() => parseProjectsOption(" , ")).toThrow(/at least one/);
    expect(() => parseProjectsOption("__abra_treasury__")).toThrow(/reserved/);
  });

  it("describes rules by peer name; unpairing drops that peer's rules", () => {
    const { receiver, sourceId } = makePair();
    const v = upsertAcceptRule(
      upsertAcceptRule(receiver, { from: sourceId.id, projects: ["app"], auto: true }).vault,
      { from: "*", projects: "*", auto: false },
    ).vault;
    expect(describeAcceptRule(v, v.syncAccept![0])).toBe("auto-apply  from mbp  ·  app");
    expect(describeAcceptRule(v, v.syncAccept![1])).toBe("queue  from all sources  ·  all projects");
    const after = removePeer(v, "mbp").vault;
    expect(after.syncAccept).toEqual([{ from: "*", projects: "*", auto: false }]);
  });
});
