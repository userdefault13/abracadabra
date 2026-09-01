import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import {
  findGrant,
  issueGrant,
  listGrants,
  revokeAll,
} from "./grants.js";

describe("grants", () => {
  beforeEach(() => {
    revokeAll();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("issues and finds a grant", () => {
    issueGrant("curl", "myproj", 300);
    const grant = findGrant("curl", "myproj");
    expect(grant).toBeDefined();
    expect(grant!.project).toBe("myproj");
  });

  it("expires grants after TTL", () => {
    issueGrant("curl", "myproj", 60);
    vi.advanceTimersByTime(61_000);
    expect(findGrant("curl", "myproj")).toBeUndefined();
  });

  it("lists grants with remaining seconds", () => {
    issueGrant("node", "a", 120);
    const listed = listGrants();
    expect(listed).toHaveLength(1);
    expect(listed[0].remainingSec).toBeGreaterThan(0);
    expect(listed[0].appId).toBe("node");
  });

  it("revokes all grants", () => {
    issueGrant("a", "p1", 60);
    issueGrant("b", "p2", 60);
    expect(revokeAll()).toBe(2);
    expect(listGrants()).toHaveLength(0);
  });
});
