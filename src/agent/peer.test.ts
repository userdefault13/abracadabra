import { describe, it, expect } from "vitest";
import type net from "node:net";
import {
  parseSsUnixXpn,
  resolvePeerPidFromSs,
  parseSocketInode,
  parseProcCmdline,
  parseProcEnviron,
  isAllowedAbraCliPeer,
  nodeOptionsAreDangerous,
  authorizePeer,
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
    const r = await authorizePeer(fakeSocket(), {
      platform: "linux",
      getSocketFd: () => 20,
      readlinkSync: () => "socket:[40321]",
      runSs: async () => {
        throw new Error("ss_not_found");
      },
    });
    expect(r).toEqual({ ok: false, reason: "ss_failed" });
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
});
