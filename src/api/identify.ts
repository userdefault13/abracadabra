import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface PeerIdentity {
  /** Stable identifier for the requesting program (best-effort). */
  appId: string;
  /** Human-readable description including PID. */
  display: string;
}

/**
 * Best-effort identification of the process holding the peer connection.
 * Uses lsof to map the client's ephemeral TCP port to a PID, then ps for the
 * full command line. Returns "unknown" when it cannot be determined.
 */
export async function identifyPeer(clientPort: number): Promise<PeerIdentity> {
  try {
    const { stdout } = await execFileAsync("lsof", [
      "-nP",
      "-iTCP:" + clientPort,
      "-sTCP:ESTABLISHED",
    ]);
    const lines = stdout.trim().split("\n").slice(1);
    for (const line of lines) {
      const cols = line.split(/\s+/);
      if (cols.length < 2) continue;
      const name = cols[0];
      const pid = cols[1];
      // lsof lists both ends of the connection; the addr col looks like
      // "127.0.0.1:54321->127.0.0.1:7331". Only the row whose LOCAL side
      // (left of "->") carries the client's ephemeral port is our requester.
      const addrCol = cols.find((c) => c?.includes("->")) ?? "";
      const [localAddr] = addrCol.split("->");
      const localPortStr = localAddr?.match(/:(\d+)$/)?.[1];
      if (localPortStr && Number(localPortStr) === clientPort) {
        let cmdline = "";
        try {
          const res = await execFileAsync("ps", ["-p", pid, "-o", "command="]);
          cmdline = res.stdout.trim();
        } catch {
          cmdline = name;
        }
        const appId = cmdline || name;
        return { appId, display: `${appId} (pid ${pid})` };
      }
    }
  } catch {
    // fallthrough
  }
  return { appId: "unknown", display: "unknown process" };
}
