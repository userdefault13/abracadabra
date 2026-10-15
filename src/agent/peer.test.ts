import { describe, it, expect } from "vitest";
import type net from "node:net";
import path from "node:path";
import {
  parseSsUnixXpn,
  resolvePeerPidFromSs,
  parseSocketInode,
  parseProcCmdline,
  parseProcEnviron,
  isAllowedAbraCliPeer,
  nodeOptionsAreDangerous,
  authorizePeer,
  classifySsError,
  peerFailureHint,
  resolvePeerFromSs,
  ssOutputLacksPeerInfo,
  SsRunError,
  SS_MAX_ATTEMPTS,
  SS_NETLINK_HINT,
  SS_RETRY_HINT,
  SS_TIMEOUT_MS,
  type PeerCheckDeps,
} from "./peer.js";

/** Realistic `ss -xpn` excerpt (iproute2 unix ESTAB + users). */
const SS_FIXTURE = `
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
u_str LISTEN 0      0      /run/user/1000/abra/agent.sock 40001 * 0
u_str ESTAB  0      0      /run/user/1000/abra/agent.sock 40321 * 40322 users:(("node",pid=1111,fd=20))
u_str ESTAB  0      0      * 40322 * 40321 users:(("node",pid=2222,fd=3))
u_str ESTAB  0      0      /tmp/other.sock 50001 * 50002 users:(("curl",pid=3333,fd=5))
u_str ESTAB  0      0      * 50002 * 50001 users:(("bash",pid=4444,fd=4))
`.trim();

describe("parseSsUnixXpn / resolvePeerPidFromSs", () => {
  it("parses fixture and finds the peer pid for the agent inode", () => {
    const entries = parseSsUnixXpn(SS_FIXTURE);
    expect(entries.length).toBeGreaterThanOrEqual(4);
    // LISTEN row skipped (no ESTAB inode pair with peer)
    expect(entries.every((e) => e.localInode > 0 && e.peerInode > 0)).toBe(true);

    const peerPid = resolvePeerPidFromSs(entries, 40321);
    expect(peerPid).toBe(2222);
  });

  it("rejects when local inode is missing", () => {
    const entries = parseSsUnixXpn(SS_FIXTURE);
    expect(resolvePeerPidFromSs(entries, 99999)).toBeNull();
  });

  it("rejects ambiguous duplicate local inodes", () => {
    const dup = `
u_str ESTAB 0 0 /run/agent.sock 40321 * 40322 users:(("node",pid=1111,fd=20))
u_str ESTAB 0 0 /run/agent.sock 40321 * 40323 users:(("node",pid=1112,fd=21))
u_str ESTAB 0 0 * 40322 * 40321 users:(("node",pid=2222,fd=3))
`.trim();
    expect(resolvePeerPidFromSs(parseSsUnixXpn(dup), 40321)).toBeNull();
  });

  it("rejects when peer endpoint has no users pid", () => {
    const noUsers = `
u_str ESTAB 0 0 /run/agent.sock 40321 * 40322 users:(("node",pid=1111,fd=20))
u_str ESTAB 0 0 * 40322 * 40321
`.trim();
    expect(resolvePeerPidFromSs(parseSsUnixXpn(noUsers), 40321)).toBeNull();
  });

  it("rejects malformed ss output", () => {
    expect(parseSsUnixXpn("garbage\nnot ss\n")).toEqual([]);
    expect(resolvePeerPidFromSs([], 1)).toBeNull();
  });

  it("still resolves when the peer pid holds an unrelated extra socket", () => {
    // Legitimate abra CLI may also hold D-Bus / Secret Service sockets (keytar).
    // Pairing is uniquely determined by inodes; same pid on other rows is OK.
    const withExtra = `
u_str ESTAB 0 0 /run/agent.sock 40321 * 40322 users:(("node",pid=1111,fd=20))
u_str ESTAB 0 0 * 40322 * 40321 users:(("node",pid=2222,fd=3))
u_str ESTAB 0 0 * 60001 * 60002 users:(("node",pid=2222,fd=10))
u_str ESTAB 0 0 * 60002 * 60001 users:(("dbus-daemon",pid=5555,fd=12))
`.trim();
    expect(resolvePeerPidFromSs(parseSsUnixXpn(withExtra), 40321)).toBe(2222);
  });

  it("drops pid when a line has multiple users:(...) groups", () => {
    const multiUsers = `
u_str ESTAB 0 0 /run/agent.sock 40321 * 40322 users:(("node",pid=1111,fd=20))
u_str ESTAB 0 0 * 40322 * 40321 users:(("node",pid=2222,fd=3)) users:(("evil",pid=9999,fd=4))
`.trim();
    expect(resolvePeerPidFromSs(parseSsUnixXpn(multiUsers), 40321)).toBeNull();
  });
});

describe("parseSocketInode / cmdline / environ", () => {
  it("parses socket:[inode]", () => {
    expect(parseSocketInode("socket:[40321]")).toBe(40321);
    expect(parseSocketInode("pipe:[1]")).toBeNull();
    expect(parseSocketInode("")).toBeNull();
  });

  it("parses null-separated cmdline and environ", () => {
    expect(parseProcCmdline(Buffer.from("node\0/opt/abra/dist/index.js\0ls\0"))).toEqual([
      "node",
      "/opt/abra/dist/index.js",
      "ls",
    ]);
    const env = parseProcEnviron(
      Buffer.from("HOME=/home/u\0NODE_OPTIONS=--require x\0PATH=/bin\0"),
    );
    expect(env.get("NODE_OPTIONS")).toBe("--require x");
    expect(env.get("HOME")).toBe("/home/u");
  });
});

describe("isAllowedAbraCliPeer", () => {
  const node = "/usr/bin/node";
  const cli = "/opt/abra/dist/index.js";
  const realpathSync = (p: string) => {
    if (p === "/usr/local/bin/abra") return cli;
    if (p === cli || p === node) return p;
    if (p.endsWith("/index.js")) return cli;
    return p;
  };

  it("allows clean node + dist/index.js argv", () => {
    const r = isAllowedAbraCliPeer({
      peerExeRealpath: node,
      agentExecRealpath: node,
      peerArgv: [node, cli, "ls"],
      cliEntrypointRealpath: cli,
      realpathSync,
    });
    expect(r).toEqual({ allowed: true });
  });

  it("allows installed abra bin that realpaths to dist/index.js", () => {
    const r = isAllowedAbraCliPeer({
      peerExeRealpath: node,
      agentExecRealpath: node,
      peerArgv: [node, "/usr/local/bin/abra", "get", "p", "K"],
      cliEntrypointRealpath: cli,
      realpathSync,
    });
    expect(r).toEqual({ allowed: true });
  });

  it("rejects exe mismatch", () => {
    const r = isAllowedAbraCliPeer({
      peerExeRealpath: "/usr/bin/other-node",
      agentExecRealpath: node,
      peerArgv: [node, cli],
      cliEntrypointRealpath: cli,
      realpathSync,
    });
    expect(r).toEqual({ allowed: false, reason: "exe_mismatch" });
  });

  it("rejects argv[1] script mismatch", () => {
    const r = isAllowedAbraCliPeer({
      peerExeRealpath: node,
      agentExecRealpath: node,
      peerArgv: [node, "/tmp/evil.js"],
      cliEntrypointRealpath: cli,
      realpathSync,
    });
    expect(r).toEqual({ allowed: false, reason: "argv_script_mismatch" });
  });

  it("rejects node flags before the script", () => {
    const r = isAllowedAbraCliPeer({
      peerExeRealpath: node,
      agentExecRealpath: node,
      peerArgv: [node, "--require", "/tmp/evil.js", cli],
      cliEntrypointRealpath: cli,
      realpathSync,
    });
    expect(r).toEqual({ allowed: false, reason: "node_flags_in_argv" });
  });

  it("rejects dangerous NODE_OPTIONS", () => {
    expect(nodeOptionsAreDangerous("--require /tmp/x.js")).toBe(true);
    expect(nodeOptionsAreDangerous("--inspect=9229")).toBe(true);
    expect(nodeOptionsAreDangerous("--max-old-space-size=128")).toBe(false);
    const r = isAllowedAbraCliPeer({
      peerExeRealpath: node,
      agentExecRealpath: node,
      peerArgv: [node, cli],
      cliEntrypointRealpath: cli,
      nodeOptions: "--import ./hook.mjs",
      realpathSync,
    });
    expect(r).toEqual({ allowed: false, reason: "dangerous_node_options" });
  });

  it("resolves relative argv[1] against peer cwd (allowed when it is the entrypoint)", () => {
    const relative = "usr/lib/abracadabra/dist/index.js";
    const peerCwd = "/";
    const r = isAllowedAbraCliPeer({
      peerExeRealpath: node,
      agentExecRealpath: node,
      peerArgv: [node, relative, "ls"],
      cliEntrypointRealpath: cli,
      peerCwd,
      realpathSync: (p) => {
        if (p === path.resolve(peerCwd, relative)) return cli;
        return realpathSync(p);
      },
    });
    expect(r).toEqual({ allowed: true });
  });

  it("rejects relative argv[1] when peer cwd differs (agent-cwd resolution would match)", () => {
    // Attacker runs from /tmp/evil with relative path that would realpath to
    // the real entrypoint if resolved against the agent's cwd (/).
    const relative = "usr/lib/abracadabra/dist/index.js";
    const agentCwd = "/";
    const peerCwd = "/tmp/evil";
    const r = isAllowedAbraCliPeer({
      peerExeRealpath: node,
      agentExecRealpath: node,
      peerArgv: [node, relative, "ls"],
      cliEntrypointRealpath: cli,
      peerCwd,
      realpathSync: (p) => {
        // Peer-cwd resolution → malicious copy, not the real entrypoint.
        if (p === path.resolve(peerCwd, relative)) return "/tmp/evil/" + relative;
        // Agent-cwd resolution would "match" the real CLI — must not be used.
        if (p === path.resolve(agentCwd, relative) || p === relative) return cli;
        return realpathSync(p);
      },
    });
    expect(r).toEqual({ allowed: false, reason: "argv_script_mismatch" });
  });

  it("rejects relative argv[1] when peer cwd is unreadable", () => {
    const r = isAllowedAbraCliPeer({
      peerExeRealpath: node,
      agentExecRealpath: node,
      peerArgv: [node, "usr/lib/abracadabra/dist/index.js", "ls"],
      cliEntrypointRealpath: cli,
      // peerCwd omitted
      realpathSync,
    });
    expect(r).toEqual({ allowed: false, reason: "peer_cwd_unreadable" });
  });

  it("leaves absolute argv[1] unaffected (no peer cwd needed)", () => {
    const r = isAllowedAbraCliPeer({
      peerExeRealpath: node,
      agentExecRealpath: node,
      peerArgv: [node, cli, "ls"],
      cliEntrypointRealpath: cli,
      // no peerCwd
      realpathSync,
    });
    expect(r).toEqual({ allowed: true });
  });
});

describe("authorizePeer (injected, no real /proc or ss)", () => {
  function fakeSocket(): net.Socket {
    return {} as net.Socket;
  }

  it("rejects on non-linux", async () => {
    const r = await authorizePeer(fakeSocket(), { platform: "darwin" });
    expect(r).toEqual({ ok: false, reason: "peer_check_linux_only" });
  });

  it("allows when injected ss + proc match the abra CLI", async () => {
    const node = "/usr/bin/node";
    const cli = "/opt/abra/dist/index.js";
    const deps: PeerCheckDeps = {
      platform: "linux",
      execPath: node,
      cliEntrypoint: cli,
      getSocketFd: () => 20,
      readlinkSync: (p) => {
        if (p === "/proc/self/fd/20") return "socket:[40321]";
        throw new Error("unexpected readlink " + p);
      },
      runSs: async () => SS_FIXTURE,
      realpathSync: (p) => {
        if (p === `/proc/2222/exe`) return node;
        if (p === node || p === cli) return p;
        return p;
      },
      readFileSync: (p) => {
        if (p === "/proc/2222/cmdline") {
          return Buffer.from(`${node}\0${cli}\0ls\0`);
        }
        if (p === "/proc/2222/environ") {
          return Buffer.from("PATH=/usr/bin\0HOME=/home/u\0");
        }
        throw new Error("unexpected read " + p);
      },
      existsSync: () => true,
    };
    const r = await authorizePeer(fakeSocket(), deps);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.pid).toBe(2222);
      expect(r.exe).toBe(node);
    }
  });

  it("rejects when ss is missing / fails", async () => {
    let calls = 0;
    const r = await authorizePeer(fakeSocket(), {
      platform: "linux",
      getSocketFd: () => 20,
      readlinkSync: () => "socket:[40321]",
      runSs: async () => {
        calls++;
        throw new SsRunError("not_found");
      },
      sleep: async () => {},
      log: () => {},
    });
    expect(r).toEqual({ ok: false, reason: "ss_failed:not_found" });
    expect(calls).toBe(1); // missing binary is not retried
  });

  it("rejects exe mismatch via injected proc", async () => {
    const node = "/usr/bin/node";
    const cli = "/opt/abra/dist/index.js";
    const r = await authorizePeer(fakeSocket(), {
      platform: "linux",
      execPath: node,
      cliEntrypoint: cli,
      getSocketFd: () => 20,
      readlinkSync: () => "socket:[40321]",
      runSs: async () => SS_FIXTURE,
      realpathSync: (p) => {
        if (p === `/proc/2222/exe`) return "/usr/bin/python3";
        if (p === node || p === cli) return p;
        return p;
      },
      readFileSync: (p) => {
        if (p.includes("cmdline")) return Buffer.from(`python3\0${cli}\0`);
        if (p.includes("environ")) return Buffer.from("PATH=/usr/bin\0");
        throw new Error(p);
      },
    });
    expect(r).toEqual({ ok: false, reason: "exe_mismatch" });
  });

  it("rejects relative argv[1] when peer cwd is unreadable", async () => {
    const node = "/usr/bin/node";
    const cli = "/opt/abra/dist/index.js";
    const relative = "usr/lib/abracadabra/dist/index.js";
    const r = await authorizePeer(fakeSocket(), {
      platform: "linux",
      execPath: node,
      cliEntrypoint: cli,
      getSocketFd: () => 20,
      readlinkSync: (p) => {
        if (p === "/proc/self/fd/20") return "socket:[40321]";
        // /proc/2222/cwd unreadable
        throw new Error("cwd unreadable");
      },
      runSs: async () => SS_FIXTURE,
      realpathSync: (p) => {
        if (p === `/proc/2222/exe`) return node;
        if (p === node || p === cli) return p;
        return p;
      },
      readFileSync: (p) => {
        if (p === "/proc/2222/cmdline") {
          return Buffer.from(`${node}\0${relative}\0ls\0`);
        }
        if (p === "/proc/2222/environ") {
          return Buffer.from("PATH=/usr/bin\0");
        }
        throw new Error("unexpected read " + p);
      },
    });
    expect(r).toEqual({ ok: false, reason: "peer_cwd_unreadable" });
  });

  it("allows relative argv[1] resolved against peer cwd to the real entrypoint", async () => {
    const node = "/usr/bin/node";
    const cli = "/opt/abra/dist/index.js";
    const relative = "opt/abra/dist/index.js";
    const peerCwd = "/";
    const r = await authorizePeer(fakeSocket(), {
      platform: "linux",
      execPath: node,
      cliEntrypoint: cli,
      getSocketFd: () => 20,
      readlinkSync: (p) => {
        if (p === "/proc/self/fd/20") return "socket:[40321]";
        if (p === "/proc/2222/cwd") return peerCwd;
        throw new Error("unexpected readlink " + p);
      },
      runSs: async () => SS_FIXTURE,
      realpathSync: (p) => {
        if (p === `/proc/2222/exe`) return node;
        if (p === path.resolve(peerCwd, relative)) return cli;
        if (p === node || p === cli) return p;
        return p;
      },
      readFileSync: (p) => {
        if (p === "/proc/2222/cmdline") {
          return Buffer.from(`${node}\0${relative}\0ls\0`);
        }
        if (p === "/proc/2222/environ") {
          return Buffer.from("PATH=/usr/bin\0");
        }
        throw new Error("unexpected read " + p);
      },
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.pid).toBe(2222);
  });
});

describe("ss error classification", () => {
  it("classifies execFile rejections", () => {
    expect(classifySsError({ killed: true, signal: "SIGTERM", code: null }).kind).toBe("timeout");
    expect(classifySsError({ code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" }).kind).toBe("maxbuffer");
    expect(classifySsError({ code: "ENOENT" }).kind).toBe("not_found");
    expect(classifySsError({ code: "EACCES" }).kind).toBe("spawn");
    expect(classifySsError(new Error("boom")).kind).toBe("spawn");
    const exit = classifySsError({ code: 2, stderr: "bad filter" });
    expect(exit.kind).toBe("exit");
    expect(exit.exitCode).toBe(2);
  });

  it("classifies sock_diag denial from stderr as netlink", () => {
    for (const stderr of [
      "Cannot open netlink socket: Address family not supported by protocol",
      "Cannot open netlink socket: Operation not permitted",
    ]) {
      expect(classifySsError({ code: 1, stderr }).kind).toBe("netlink");
    }
  });

  it("a timeout is never classified as netlink even with noisy stderr", () => {
    expect(
      classifySsError({ killed: true, code: null, stderr: "Operation not permitted" }).kind,
    ).toBe("timeout");
  });

  it("detects ss falling back to /proc/net/unix (no peer inodes)", () => {
    const procFallback = `
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port
u_str ESTAB 0 0 /run/user/1000/abra/agent.sock 40321 * 0 users:(("node",pid=1111,fd=20))
u_str ESTAB 0 0 * 40322 * 0 users:(("node",pid=2222,fd=3))
`.trim();
    expect(ssOutputLacksPeerInfo(procFallback)).toBe(true);
    expect(ssOutputLacksPeerInfo(SS_FIXTURE)).toBe(false);
    expect(ssOutputLacksPeerInfo("")).toBe(false);
  });
});

describe("peerFailureHint", () => {
  const agent = { execPath: "/usr/bin/node", cliEntrypoint: "/usr/lib/abracadabra/dist/index.js" };

  it("netlink hint only for sock_diag failures", () => {
    expect(peerFailureHint("ss_failed:netlink", agent)).toBe(SS_NETLINK_HINT);
    expect(peerFailureHint("ss_no_peer_info", agent)).toBe(SS_NETLINK_HINT);
    expect(peerFailureHint("ss_failed:timeout", agent)).toBe(SS_RETRY_HINT);
    expect(peerFailureHint("ss_failed:timeout", agent)).not.toContain("AF_NETLINK");
    expect(peerFailureHint("ss_failed:exit_1", agent)).not.toContain("AF_NETLINK");
    expect(peerFailureHint("ss_failed:maxbuffer", agent)).toMatch(/retry/);
  });

  it("exe_mismatch names the agent's node and the exact rerun form", () => {
    const h = peerFailureHint("exe_mismatch", agent)!;
    expect(h).toContain("/usr/bin/node");
    expect(h).toContain(
      "Rerun: /usr/bin/node /usr/lib/abracadabra/dist/index.js unlock",
    );
  });

  it("no hint for policy rejections that must not be coached", () => {
    expect(peerFailureHint("dangerous_node_options", agent)).toBeUndefined();
    expect(peerFailureHint("node_flags_in_argv", agent)).toBeUndefined();
  });
});

describe("resolvePeerFromSs details", () => {
  it("multiple holders of the peer socket in one users:() group → no pid", () => {
    const shared = `
u_str ESTAB 0 0 /run/agent.sock 40321 * 40322 users:(("node",pid=1111,fd=20))
u_str ESTAB 0 0 * 40322 * 40321 users:(("node",pid=2222,fd=3),("evil",pid=9999,fd=4))
`.trim();
    const r = resolvePeerFromSs(parseSsUnixXpn(shared), 40321);
    expect(r.ok).toBe(false);
    expect(resolvePeerPidFromSs(parseSsUnixXpn(shared), 40321)).toBeNull();
  });

  it("missing rows are retryable; duplicates are not", () => {
    expect(resolvePeerFromSs([], 40321)).toMatchObject({
      ok: false,
      detail: "local_not_found",
      retryable: true,
    });
    const onlyOurs = parseSsUnixXpn(
      `u_str ESTAB 0 0 /run/agent.sock 40321 * 40322 users:(("node",pid=1111,fd=20))`,
    );
    expect(resolvePeerFromSs(onlyOurs, 40321)).toMatchObject({
      detail: "peer_not_found",
      retryable: true,
    });
    const dup = parseSsUnixXpn(`
u_str ESTAB 0 0 /run/agent.sock 40321 * 40322 users:(("node",pid=1111,fd=20))
u_str ESTAB 0 0 /run/agent.sock 40321 * 40323 users:(("node",pid=1111,fd=21))
`);
    expect(resolvePeerFromSs(dup, 40321)).toMatchObject({
      detail: "ambiguous",
      retryable: false,
    });
  });
});

describe("authorizePeer ss retry / backoff", () => {
  const node = "/usr/bin/node";
  const cli = "/opt/abra/dist/index.js";
  const SS_WITHOUT_PEER_ROW = SS_FIXTURE.split("\n")
    .filter((l) => !l.includes("* 40322 * 40321"))
    .join("\n");

  function deps(
    runSs: PeerCheckDeps["runSs"],
    extra: { procReads?: string[]; sleeps?: number[]; logs?: string[] } = {},
  ): PeerCheckDeps {
    return {
      platform: "linux",
      execPath: node,
      cliEntrypoint: cli,
      getSocketFd: () => 20,
      readlinkSync: (p) => {
        if (p === "/proc/self/fd/20") return "socket:[40321]";
        throw new Error("unexpected readlink " + p);
      },
      runSs,
      realpathSync: (p) => {
        extra.procReads?.push(p);
        if (p === "/proc/2222/exe") return node;
        if (p === "/proc/9999/exe") return "/usr/bin/python3";
        return p;
      },
      readFileSync: (p) => {
        extra.procReads?.push(p);
        if (p.endsWith("/cmdline")) return Buffer.from(`${node}\0${cli}\0unlock\0`);
        if (p.endsWith("/environ")) return Buffer.from("PATH=/usr/bin\0");
        throw new Error("unexpected read " + p);
      },
      sleep: async (ms) => {
        extra.sleeps?.push(ms);
      },
      log: (m) => {
        extra.logs?.push(m);
      },
    };
  }

  it("timeout then success → ok, with backoff", async () => {
    let calls = 0;
    const sleeps: number[] = [];
    const timeouts: number[] = [];
    const r = await authorizePeer(
      {} as net.Socket,
      deps(
        async ({ timeoutMs }) => {
          timeouts.push(timeoutMs);
          if (++calls === 1) throw new SsRunError("timeout");
          return SS_FIXTURE;
        },
        { sleeps },
      ),
    );
    expect(r).toMatchObject({ ok: true, pid: 2222 });
    expect(calls).toBe(2);
    expect(sleeps).toEqual([100]);
    expect(timeouts[0]).toBe(SS_TIMEOUT_MS);
  });

  it("three timeouts → ss_failed:timeout, logged per attempt", async () => {
    let calls = 0;
    const logs: string[] = [];
    const sleeps: number[] = [];
    const r = await authorizePeer(
      {} as net.Socket,
      deps(
        async () => {
          calls++;
          throw Object.assign(new Error("Command failed"), {
            killed: true,
            signal: "SIGTERM",
            code: null,
          });
        },
        { logs, sleeps },
      ),
    );
    expect(r).toEqual({ ok: false, reason: "ss_failed:timeout" });
    expect(calls).toBe(SS_MAX_ATTEMPTS);
    expect(sleeps).toEqual([100, 300]);
    expect(logs).toEqual([
      "ss_failed:timeout attempt=1/3",
      "ss_failed:timeout attempt=2/3",
      "ss_failed:timeout attempt=3/3",
    ]);
  });

  it("netlink denial is not retried", async () => {
    let calls = 0;
    const r = await authorizePeer(
      {} as net.Socket,
      deps(async () => {
        calls++;
        throw {
          code: 1,
          stderr: "Cannot open netlink socket: Address family not supported by protocol",
        };
      }),
    );
    expect(r).toEqual({ ok: false, reason: "ss_failed:netlink" });
    expect(calls).toBe(1);
  });

  it("ss /proc fallback output (no peer inodes) → ss_no_peer_info", async () => {
    const r = await authorizePeer(
      {} as net.Socket,
      deps(async () => "u_str ESTAB 0 0 /run/agent.sock 40321 * 0\nu_str ESTAB 0 0 * 40322 * 0\n"),
    );
    expect(r).toEqual({ ok: false, reason: "ss_no_peer_info" });
  });

  it("peer inode not visible yet, then visible → ok", async () => {
    let calls = 0;
    const r = await authorizePeer(
      {} as net.Socket,
      deps(async () => (++calls === 1 ? SS_WITHOUT_PEER_ROW : SS_FIXTURE)),
    );
    expect(r).toMatchObject({ ok: true, pid: 2222 });
    expect(calls).toBe(2);
  });

  it("peer never visible → peer_pid_unresolved after 3 attempts", async () => {
    let calls = 0;
    const r = await authorizePeer(
      {} as net.Socket,
      deps(async () => {
        calls++;
        return SS_WITHOUT_PEER_ROW;
      }),
    );
    expect(r).toEqual({ ok: false, reason: "peer_pid_unresolved:peer_not_found" });
    expect(calls).toBe(3);
  });

  it("never accepts a wrong pid: ambiguous snapshot is not retried and no /proc is read", async () => {
    const procReads: string[] = [];
    let calls = 0;
    const ambiguous = `
u_str ESTAB 0 0 /run/agent.sock 40321 * 40322 users:(("node",pid=1111,fd=20))
u_str ESTAB 0 0 * 40322 * 40321 users:(("node",pid=2222,fd=3))
u_str ESTAB 0 0 * 40322 * 40321 users:(("evil",pid=9999,fd=3))
`.trim();
    const r = await authorizePeer(
      {} as net.Socket,
      deps(
        async () => {
          calls++;
          return calls === 1 ? ambiguous : SS_FIXTURE;
        },
        { procReads },
      ),
    );
    expect(r).toEqual({ ok: false, reason: "peer_pid_unresolved:ambiguous" });
    expect(calls).toBe(1);
    expect(procReads.filter((p) => p.startsWith("/proc/"))).toEqual([]);
  });

  it("never accepts a wrong pid: a retry that resolves to another process is still exe-checked", async () => {
    let calls = 0;
    const evilPeer = SS_FIXTURE.replace("pid=2222", "pid=9999");
    const r = await authorizePeer(
      {} as net.Socket,
      deps(async () => (++calls === 1 ? SS_WITHOUT_PEER_ROW : evilPeer)),
    );
    expect(r).toEqual({ ok: false, reason: "exe_mismatch" });
  });

  it("stops retrying once the overall budget is spent", async () => {
    let t = 0;
    let calls = 0;
    const d = deps(async ({ timeoutMs }) => {
      calls++;
      t += timeoutMs; // each attempt burns its full timeout
      throw new SsRunError("timeout");
    });
    d.now = () => t;
    const r = await authorizePeer({} as net.Socket, d);
    expect(r).toEqual({ ok: false, reason: "ss_failed:timeout" });
    expect(t).toBeLessThanOrEqual(12_000);
    expect(calls).toBe(3);
  });
});
