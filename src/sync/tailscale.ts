import { execFile } from "node:child_process";
import net from "node:net";

export type ExecFileFn = (
  file: string,
  args: string[],
  opts: { timeout: number },
) => Promise<{ stdout: string }>;

const defaultExecFile: ExecFileFn = (file, args, opts) =>
  new Promise((resolve, reject) => {
    execFile(file, args, { timeout: opts.timeout, windowsHide: true, encoding: "utf8" }, (err, stdout) => {
      if (err) reject(err);
      else resolve({ stdout });
    });
  });

export function tailscaleCandidates(platform: NodeJS.Platform = process.platform): string[] {
  return platform === "darwin"
    ? ["tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale"]
    : ["tailscale"];
}

/** Tailscale assigns IPv4 addresses from the CGNAT range 100.64.0.0/10. */
export function isTailscaleIPv4(ip: string): boolean {
  if (!net.isIPv4(ip)) return false;
  const [a, b] = ip.split(".").map(Number);
  return a === 100 && b >= 64 && b <= 127;
}

/** This machine's Tailscale IPv4 via `tailscale ip -4`, or null when unavailable. */
export async function detectTailscaleIPv4(
  opts: { execFile?: ExecFileFn; timeoutMs?: number; candidates?: string[] } = {},
): Promise<string | null> {
  const run = opts.execFile ?? defaultExecFile;
  for (const bin of opts.candidates ?? tailscaleCandidates()) {
    try {
      const { stdout } = await run(bin, ["ip", "-4"], { timeout: opts.timeoutMs ?? 3000 });
      const ip = stdout
        .split(/\r?\n/)
        .map((l) => l.trim())
        .find(isTailscaleIPv4);
      if (ip) return ip;
    } catch {
      /* not installed / not running / timed out — try the next candidate */
    }
  }
  return null;
}
