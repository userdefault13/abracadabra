import { describe, it, expect } from "vitest";
import {
  identityForPid,
  identifyMcpCaller,
  type CallerIdentityFs,
} from "./caller-identity.js";

function makeFs(opts: {
  readlink?: string | (() => never);
  realpath?: string | (() => never);
  stat?: { dev: number; ino: number } | (() => never);
}): CallerIdentityFs {
  return {
    readlink: () => {
      if (typeof opts.readlink === "function") opts.readlink();
      return opts.readlink as string;
    },
    realpath: () => {
      if (typeof opts.realpath === "function") opts.realpath();
      return (opts.realpath as string) ?? (opts.readlink as string);
    },
    stat: () => {
      if (typeof opts.stat === "function") opts.stat();
      return opts.stat as { dev: number; ino: number };
    },
  };
}

describe("caller-identity", () => {
  it("injected readlink/realpath/stat → identity", async () => {
    const id = await identityForPid(42, {
      platform: "linux",
      fs: makeFs({
        readlink: "/opt/client/bin",
        realpath: "/opt/client/bin",
        stat: { dev: 10, ino: 99 },
      }),
    });
    expect(id).toEqual({ exe: "/opt/client/bin", dev: 10, ino: 99 });
  });

  it('"(deleted)" → null', async () => {
    const id = await identityForPid(1, {
      platform: "linux",
      fs: makeFs({
        readlink: "/usr/bin/node (deleted)",
        realpath: "/usr/bin/node",
        stat: { dev: 1, ino: 1 },
      }),
    });
    expect(id).toBeNull();
  });

  it("failure → null", async () => {
    const id = await identityForPid(1, {
      platform: "linux",
      fs: makeFs({
        readlink: () => {
          throw new Error("ENOENT");
        },
      }),
    });
    expect(id).toBeNull();
  });

  it("non-linux → null", async () => {
    const id = await identityForPid(1, {
      platform: "darwin",
      fs: makeFs({
        readlink: "/bin/x",
        realpath: "/bin/x",
        stat: { dev: 1, ino: 1 },
      }),
    });
    expect(id).toBeNull();
  });

  it("MCP uses ppid (not requestedBy)", async () => {
    const id = await identifyMcpCaller({
      platform: "linux",
      ppid: 777,
      fs: makeFs({
        readlink: "/client",
        realpath: "/client",
        stat: { dev: 2, ino: 3 },
      }),
    });
    expect(id).toEqual({ exe: "/client", dev: 2, ino: 3 });
  });
});
