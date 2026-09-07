import { EventEmitter } from "node:events";
import { describe, it, expect, beforeEach, vi } from "vitest";

// A tiny controllable stand-in for `security`: `find` answers come from
// `findQueue`, and anything written to `security -i` stdin is captured.
type ExecCb = (err: (Error & { code?: number; stderr?: string }) | null, out?: { stdout: string; stderr: string }) => void;
const state = {
  findQueue: [] as Array<{ stdout?: string; code?: number; stderr?: string }>,
  execCalls: [] as string[][],
  stdinLines: [] as string[],
  spawnCalls: [] as string[][],
  spawnExit: 0,
  spawnStderr: "",
};

vi.mock("node:child_process", () => ({
  execFile: (cmd: string, args: string[], cb: ExecCb) => {
    state.execCalls.push([cmd, ...args]);
    const next = state.findQueue.shift() ?? { stdout: "" };
    if (next.code != null) {
      const err = Object.assign(new Error(`Command failed: ${cmd} ${args.join(" ")}`), {
        code: next.code,
        stderr: next.stderr ?? "",
      });
      cb(err);
    } else {
      cb(null, { stdout: next.stdout ?? "", stderr: "" });
    }
  },
  spawn: (cmd: string, args: string[]) => {
    state.spawnCalls.push([cmd, ...args]);
    const child = new EventEmitter() as EventEmitter & {
      stderr: EventEmitter;
      stdin: { end: (s: string) => void };
    };
    child.stderr = new EventEmitter();
    child.stdin = {
      end: (s: string) => {
        state.stdinLines.push(s);
        setImmediate(() => {
          if (state.spawnStderr) child.stderr.emit("data", state.spawnStderr);
          child.emit("close", state.spawnExit);
        });
      },
    };
    return child;
  },
}));

const { MacOSKeychainKeystore, scrubSecurityText, KeychainError } = await import("./keystore-macos.js");

beforeEach(() => {
  state.findQueue = [];
  state.execCalls = [];
  state.stdinLines = [];
  state.spawnCalls = [];
  state.spawnExit = 0;
  state.spawnStderr = "";
});

describe("MacOSKeychainKeystore", () => {
  it("returns the existing key when the Keychain has one", async () => {
    const key = Buffer.alloc(32, 7);
    state.findQueue.push({ stdout: `${key.toString("base64")}\n` });
    const got = await new MacOSKeychainKeystore().getOrCreateMasterKey();
    expect(got.equals(key)).toBe(true);
    expect(state.spawnCalls).toHaveLength(0);
  });

  it("creates a key only when the item is genuinely missing (exit 44), passing it via stdin not argv", async () => {
    state.findQueue.push({ code: 44, stderr: "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain." });
    // storeMasterKey verifies by reading back: echo whatever was written.
    state.findQueue.push({ stdout: "" }); // placeholder, replaced below once we know the key
    const ks = new MacOSKeychainKeystore();
    // Intercept the write to feed the same value back on the verify read.
    const origPush = state.stdinLines.push.bind(state.stdinLines);
    state.stdinLines.push = (line: string) => {
      const m = line.match(/-w "([^"]+)"/);
      state.findQueue[0] = { stdout: `${m?.[1] ?? ""}\n` };
      return origPush(line);
    };
    const got = await ks.getOrCreateMasterKey();
    expect(got).toHaveLength(32);
    expect(state.spawnCalls).toEqual([["security", "-i"]]);
    const line = state.stdinLines[0];
    expect(line).toMatch(/^add-generic-password -s "abracadabra-master-key" -a ".+" -w "[A-Za-z0-9+/=]+" -U\n$/);
    // Nothing secret ever reached execFile's argv.
    for (const call of state.execCalls) expect(call.join(" ")).not.toContain(got.toString("base64"));
  });

  it("refuses to mint a new key on an access error (ssh: user interaction not allowed)", async () => {
    state.findQueue.push({ code: 36, stderr: "security: SecKeychainSearchCopyNext: User interaction is not allowed." });
    await expect(new MacOSKeychainKeystore().getOrCreateMasterKey()).rejects.toThrow(/not accessible[\s\S]*Refusing to create a new master key/);
    expect(state.spawnCalls).toHaveLength(0);
  });

  it("never echoes a -w value in a thrown error", async () => {
    state.findQueue.push({ code: 44, stderr: "not found" });
    state.spawnExit = 36;
    state.spawnStderr = "security: SecKeychainItemModifyContent: User interaction is not allowed.";
    let caught: unknown;
    try {
      await new MacOSKeychainKeystore().getOrCreateMasterKey();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(KeychainError);
    const msg = String((caught as Error).message);
    expect(msg).toMatch(/User interaction is not allowed/);
    expect(msg).not.toMatch(/[A-Za-z0-9+/]{40,}={0,2}/);
    expect(msg).not.toMatch(/-w [^<]/);
  });
});

describe("scrubSecurityText", () => {
  it("redacts quoted and bare -w values", () => {
    expect(scrubSecurityText('add-generic-password -s svc -w "c2VjcmV0" -U')).toBe(
      'add-generic-password -s svc -w <redacted> -U',
    );
    expect(scrubSecurityText("security add-generic-password -a me -w c2VjcmV0== -U\nsecurity: fail")).toBe(
      "security add-generic-password -a me -w <redacted> -U\nsecurity: fail",
    );
  });
});
