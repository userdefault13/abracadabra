import { describe, expect, it } from "vitest";
import { isNewerSemver, parseSemver } from "./semver.js";

describe("semver", () => {
  it("parses x.y.z", () => {
    expect(parseSemver("1.2.3")).toEqual([1, 2, 3]);
    expect(parseSemver("v1.2.3-beta")).toEqual([1, 2, 3]);
  });

  it("compares versions", () => {
    expect(isNewerSemver("1.0.1", "1.0.0")).toBe(true);
    expect(isNewerSemver("1.0.0", "1.0.1")).toBe(false);
    expect(isNewerSemver("2.0.0", "1.9.9")).toBe(true);
    expect(isNewerSemver("1.0.0", "1.0.0")).toBe(false);
  });
});
