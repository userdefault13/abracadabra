import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  PolkitAuth,
  POLKIT_ACTION_ID,
  MIN_PKCHECK_TIMEOUT_SECONDS,
  resolvePolkitSubject,
  probePolkit,
  setProbePolkitForTests,
  type ExecFileFn,
} from "./auth-polkit.js";

describe("PolkitAuth", () => {
  afterEach(() => {
    setProbePolkitForTests(null);
  });

  function authWith(execFile: ExecFileFn, exists: (p: string) => boolean = () => true) {
    return new PolkitAuth({
      execFile,
      existsSync: exists,
      // After comm: fields 3–21 (19 tokens) then field 22 starttime=99999
      readFileSync: () => "12345 (node) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 99999 0 0 0 0 0",
      getuid: () => 1000,
      pid: 12345,
    });
  }

  it("allows on exit 0", async () => {
    const execFile = vi.fn<ExecFileFn>().mockResolvedValue({ stdout: "", stderr: "" });
    await expect(authWith(execFile).authenticate({ reason: "reveal FOO" })).resolves.toBeUndefined();
    expect(execFile).toHaveBeenCalledTimes(1);
  });

  it.each([
    [1, /not authorized \(pkcheck exit 1\)/],
    [
      2,
      /authorization requires a challenge but user interaction was not allowed \(pkcheck exit 2\)/,
    ],
    [3, /the authentication dialog was dismissed \(pkcheck exit 3\)/],
    [127, /an error occurred while checking authorization \(pkcheck exit 127\)/],
  ] as const)("denies on exit %i with man-page message", async (status, msg) => {
    const execFile = vi.fn<ExecFileFn>().mockRejectedValue(Object.assign(new Error("fail"), { status }));
    await expect(authWith(execFile).authenticate({ reason: "reveal FOO" })).rejects.toThrow(msg);
  });

  it("denies on ENOENT spawn error", async () => {
    const execFile = vi.fn<ExecFileFn>().mockRejectedValue(
      Object.assign(new Error("spawn"), { code: "ENOENT" }),
    );
    await expect(authWith(execFile).authenticate({ reason: "x" })).rejects.toThrow(/ENOENT/);
  });

  it("denies on timeout/signal", async () => {
    const execFile = vi.fn<ExecFileFn>().mockRejectedValue(
      Object.assign(new Error("killed"), { killed: true, signal: "SIGTERM" }),
    );
    await expect(authWith(execFile).authenticate({ reason: "x" })).rejects.toThrow(/timed out|interrupted/);
  });

  it("denies without exec when pkcheck binary missing", async () => {
    const execFile = vi.fn<ExecFileFn>();
    const auth = authWith(execFile, (p) => p.endsWith("dev.abracadabra.policy"));
    const err = auth.authenticate({ reason: "reveal" });
    await expect(err).rejects.toThrow(/PolKit approval denied — reveal\. PolKit is not set up \(pkcheck not found/);
    await expect(err).rejects.toThrow(/sudo scripts\/install-polkit\.sh/);
    await expect(err).rejects.toThrow(/ABRA_AUTH=password/);
    expect(execFile).not.toHaveBeenCalled();
  });

  it("denies without exec when policy file missing", async () => {
    const execFile = vi.fn<ExecFileFn>();
    const auth = authWith(execFile, (p) => p === "/usr/bin/pkcheck");
    const err = auth.authenticate({ reason: "reveal" });
    await expect(err).rejects.toThrow(/PolKit is not set up \(polkit policy missing/);
    await expect(err).rejects.toThrow(/sudo scripts\/install-polkit\.sh/);
    expect(execFile).not.toHaveBeenCalled();
  });

  it("denies without exec when both pkcheck and policy missing", async () => {
    const execFile = vi.fn<ExecFileFn>();
    const auth = authWith(execFile, () => false);
    await expect(auth.authenticate({ reason: "reveal" })).rejects.toThrow(
      /sudo scripts\/install-polkit\.sh/,
    );
    expect(execFile).not.toHaveBeenCalled();
  });

  it("ignores probe test override — real (injected) filesystem check still denies", async () => {
    setProbePolkitForTests(() => ({ ok: true, pkcheck: "/mock", policy: "/mock.policy" }));
    const execFile = vi.fn<ExecFileFn>();
    const auth = authWith(execFile, () => false);
    await expect(auth.authenticate({ reason: "reveal" })).rejects.toThrow(/PolKit is not set up/);
    expect(execFile).not.toHaveBeenCalled();
  });

  it("execs pkcheck when both policy and pkcheck are present", async () => {
    const execFile = vi.fn<ExecFileFn>().mockResolvedValue({ stdout: "", stderr: "" });
    const auth = authWith(
      execFile,
      (p) => p === "/usr/local/bin/pkcheck" || p === "/etc/polkit-1/actions/dev.abracadabra.policy",
    );
    await expect(auth.authenticate({ reason: "reveal" })).resolves.toBeUndefined();
    expect(execFile).toHaveBeenCalledTimes(1);
    expect(execFile.mock.calls[0][0]).toBe("/usr/local/bin/pkcheck");
  });

  it("denies without exec when getuid is unavailable", async () => {
    const execFile = vi.fn<ExecFileFn>();
    const auth = new PolkitAuth({
      execFile,
      existsSync: () => true,
      // Non-function wins over process.getuid (?? only skips null/undefined)
      getuid: false as unknown as () => number,
    });
    await expect(auth.authenticate({ reason: "reveal" })).rejects.toThrow(
      /getuid is unavailable/,
    );
    expect(execFile).not.toHaveBeenCalled();
  });

  it("passes action id, allow-user-interaction, and pid,start,uid subject", async () => {
    const execFile = vi.fn<ExecFileFn>().mockResolvedValue({ stdout: "", stderr: "" });
    await authWith(execFile).authenticate({ reason: "r", timeoutSeconds: 10 });
    expect(execFile).toHaveBeenCalledWith(
      "/usr/bin/pkcheck",
      [
        "--action-id",
        POLKIT_ACTION_ID,
        "--process",
        "12345,99999,1000",
        "--allow-user-interaction",
      ],
      { timeout: MIN_PKCHECK_TIMEOUT_SECONDS * 1000 },
    );
  });

  it("does not cache — two calls => two execs", async () => {
    const execFile = vi.fn<ExecFileFn>().mockResolvedValue({ stdout: "", stderr: "" });
    const auth = authWith(execFile);
    await auth.authenticate({ reason: "a" });
    await auth.authenticate({ reason: "b" });
    expect(execFile).toHaveBeenCalledTimes(2);
  });

  it("writes nothing to stdout", async () => {
    const stdoutSpy = vi.spyOn(process.stdout, "write");
    const execFile = vi.fn<ExecFileFn>().mockResolvedValue({ stdout: "authorized\n", stderr: "" });
    await authWith(execFile).authenticate({ reason: "reveal" });
    expect(stdoutSpy).not.toHaveBeenCalled();
    stdoutSpy.mockRestore();
  });

  it("id is polkit and supportsBiometrics is false", () => {
    const auth = new PolkitAuth();
    expect(auth.id).toBe("polkit");
    expect(auth.supportsBiometrics()).toBe(false);
  });
});

describe("resolvePolkitSubject", () => {
  it("builds pid,start_time,uid from /proc/self/stat", () => {
    const subject = resolvePolkitSubject({
      pid: 42,
      getuid: () => 1001,
      readFileSync: () =>
        "42 (node) S 1 1 1 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 777 0 0 0 0 0 0 0",
    });
    // Field 22 = starttime; after comm there are 20 tokens before starttime (fields 3–22).
    expect(subject).toBe("42,777,1001");
  });

  it("falls back to plain pid when /proc parse fails", () => {
    expect(
      resolvePolkitSubject({
        pid: 9,
        readFileSync: () => {
          throw new Error("ENOENT");
        },
      }),
    ).toBe("9");
  });
});

describe("probePolkit", () => {
  afterEach(() => setProbePolkitForTests(null));

  it("ok when pkcheck and policy exist", () => {
    const exists = (p: string) =>
      p === "/usr/bin/pkcheck" || p === "/usr/share/polkit-1/actions/dev.abracadabra.policy";
    const r = probePolkit({ existsSync: exists });
    expect(r.ok).toBe(true);
    expect(r.pkcheck).toBe("/usr/bin/pkcheck");
    expect(r.policy).toContain("dev.abracadabra.policy");
  });

  it("not ok when policy missing", () => {
    const r = probePolkit({ existsSync: (p) => p === "/usr/bin/pkcheck" });
    expect(r.ok).toBe(false);
    expect(r.pkcheck).toBe("/usr/bin/pkcheck");
    expect(r.detail).toMatch(/install-polkit/);
  });

  it("honors test override", () => {
    setProbePolkitForTests(() => ({ ok: true, pkcheck: "/mock", policy: "/mock.policy" }));
    expect(probePolkit()).toEqual({ ok: true, pkcheck: "/mock", policy: "/mock.policy" });
  });
});
