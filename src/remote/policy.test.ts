import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  buildRequestedPolicy,
  clampUnlockPolicy,
  defaultUnlockCaps,
  localUnlockCaps,
  parsePolicyDuration,
} from "./policy.js";

describe("remote unlock relock policy", () => {
  const caps = { idleSeconds: 15 * 60, maxAgeSeconds: 8 * 60 * 60 };

  it("clamp to local cap when request is shorter", () => {
    expect(
      clampUnlockPolicy({ idleSeconds: 60, maxAgeSeconds: 3600 }, caps),
    ).toEqual({ idleSeconds: 60, maxAgeSeconds: 3600 });
  });

  it("hub cannot lengthen — longer request is clamped down", () => {
    expect(
      clampUnlockPolicy(
        { idleSeconds: 24 * 60 * 60, maxAgeSeconds: 48 * 60 * 60 },
        caps,
      ),
    ).toEqual({ idleSeconds: caps.idleSeconds, maxAgeSeconds: caps.maxAgeSeconds });
  });

  it("omitted fields use local caps", () => {
    expect(clampUnlockPolicy({}, caps)).toEqual(caps);
    expect(clampUnlockPolicy({ idleSeconds: 30 }, caps)).toEqual({
      idleSeconds: 30,
      maxAgeSeconds: caps.maxAgeSeconds,
    });
    expect(clampUnlockPolicy({ maxAgeSeconds: 120 }, caps)).toEqual({
      idleSeconds: caps.idleSeconds,
      maxAgeSeconds: 120,
    });
  });

  it("rejects invalid local caps", () => {
    expect(() => clampUnlockPolicy({}, { idleSeconds: 0, maxAgeSeconds: 100 })).toThrow(
      /idle cap/,
    );
    expect(() => clampUnlockPolicy({}, { idleSeconds: 100, maxAgeSeconds: -1 })).toThrow(
      /max-age cap/,
    );
  });

  it("defaultUnlockCaps matches agent defaults (15m / 8h)", () => {
    expect(defaultUnlockCaps()).toEqual({
      idleSeconds: 15 * 60,
      maxAgeSeconds: 8 * 60 * 60,
    });
  });

  describe("localUnlockCaps from env", () => {
    let idleBackup: string | undefined;
    let maxBackup: string | undefined;

    beforeEach(() => {
      idleBackup = process.env.ABRA_AGENT_IDLE_SECONDS;
      maxBackup = process.env.ABRA_AGENT_MAX_AGE_SECONDS;
    });

    afterEach(() => {
      if (idleBackup === undefined) delete process.env.ABRA_AGENT_IDLE_SECONDS;
      else process.env.ABRA_AGENT_IDLE_SECONDS = idleBackup;
      if (maxBackup === undefined) delete process.env.ABRA_AGENT_MAX_AGE_SECONDS;
      else process.env.ABRA_AGENT_MAX_AGE_SECONDS = maxBackup;
    });

    it("reads ABRA_AGENT_IDLE_SECONDS / ABRA_AGENT_MAX_AGE_SECONDS", () => {
      process.env.ABRA_AGENT_IDLE_SECONDS = "120";
      process.env.ABRA_AGENT_MAX_AGE_SECONDS = "3600";
      expect(localUnlockCaps()).toEqual({ idleSeconds: 120, maxAgeSeconds: 3600 });
    });
  });

  it("parsePolicyDuration accepts s/m/h", () => {
    expect(parsePolicyDuration("90s", "idle")).toBe(90);
    expect(parsePolicyDuration("5m", "idle")).toBe(300);
    expect(parsePolicyDuration("2h", "max-age")).toBe(7200);
    expect(parsePolicyDuration("45", "idle")).toBe(45);
  });

  it("parsePolicyDuration rejects junk", () => {
    expect(() => parsePolicyDuration("", "idle")).toThrow(/required/);
    expect(() => parsePolicyDuration("0s", "idle")).toThrow(/invalid/);
    expect(() => parsePolicyDuration("nope", "idle")).toThrow(/invalid/);
  });

  it("buildRequestedPolicy omits unset fields", () => {
    expect(buildRequestedPolicy({})).toEqual({});
    expect(buildRequestedPolicy({ idleSeconds: 60 })).toEqual({ idleSeconds: 60 });
    expect(buildRequestedPolicy({ idleSeconds: 60, maxAgeSeconds: 120 })).toEqual({
      idleSeconds: 60,
      maxAgeSeconds: 120,
    });
    expect(() => buildRequestedPolicy({ idleSeconds: 0 })).toThrow(/idle/);
  });
});
