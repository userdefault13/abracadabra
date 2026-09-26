import { spawn as defaultSpawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import fs from "node:fs";

const GDBUS = "/usr/bin/gdbus";
const DBUS_MONITOR = "/usr/bin/dbus-monitor";

const GDBUS_ARGS = [
  "monitor",
  "--system",
  "--dest",
  "org.freedesktop.login1",
  "--object-path",
  "/org/freedesktop/login1",
] as const;

const DBUS_MONITOR_ARGS = [
  "--system",
  "type='signal',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'",
] as const;

/** Restart backoff after child exit (ms). Cap at ~5 restarts then give up. */
const RESTART_BACKOFF_MS = [1000, 5000, 30_000, 60_000, 120_000] as const;
const MAX_LINE_BUF = 64 * 1024;

export type SleepWatchSpawn = (
  command: string,
  args: readonly string[],
  options: { stdio: ["ignore", "pipe", "ignore"] },
) => ChildProcessWithoutNullStreams;

export type SleepWatchExistsSync = (path: string) => boolean;

export interface SleepWatchOpts {
  onSleep: () => void;
  spawn?: SleepWatchSpawn;
  existsSync?: SleepWatchExistsSync;
  platform?: NodeJS.Platform;
  log?: (msg: string) => void;
}

export interface SleepWatchHandle {
  stop(): void;
}

export type SleepWatchFactory = (opts: { onSleep: () => void }) => SleepWatchHandle;

/**
 * Subscribe to logind PrepareForSleep(true) via gdbus or dbus-monitor subprocess.
 * Linux only; graceful no-op if binaries missing or spawn fails.
 *
 * Why a subprocess (not a native D-Bus addon): keep the agent free of native
 * deps; systemd unit already allows AF_UNIX. We do not take a logind inhibitor —
 * lock is best-effort right before suspend.
 */
export function startSleepWatch(opts: SleepWatchOpts): SleepWatchHandle {
  const platform = opts.platform ?? process.platform;
  const existsSync = opts.existsSync ?? fs.existsSync;
  const spawnFn = opts.spawn ?? (defaultSpawn as SleepWatchSpawn);
  const log =
    opts.log ??
    ((msg: string) => {
      process.stderr.write(`abra-agent: ${msg}\n`);
    });

  let stopped = false;
  let child: ChildProcessWithoutNullStreams | null = null;
  let restartTimer: NodeJS.Timeout | null = null;
  let restartCount = 0;
  let loggedUnavailable = false;
  let lineBuf = "";
  /** dbus-monitor: wait for `boolean true` after PrepareForSleep member line. */
  let expectBooleanAfterMember = false;

  const stop = (): void => {
    stopped = true;
    if (restartTimer) {
      clearTimeout(restartTimer);
      restartTimer = null;
    }
    killChild();
  };

  const killChild = (): void => {
    if (!child) return;
    const c = child;
    child = null;
    c.removeAllListeners();
    try {
      c.stdout.removeAllListeners();
    } catch {
      /* ignore */
    }
    try {
      c.kill("SIGTERM");
    } catch {
      /* ignore */
    }
  };

  const noteUnavailable = (reason: string): void => {
    if (loggedUnavailable) return;
    loggedUnavailable = true;
    log(`sleep lock unavailable: ${reason}`);
  };

  const handleLine = (line: string): void => {
    if (stopped) return;
    // gdbus: ...Manager.PrepareForSleep (true,)
    if (line.includes("PrepareForSleep") && /\(\s*true\s*,?\s*\)/.test(line)) {
      expectBooleanAfterMember = false;
      opts.onSleep();
      return;
    }
    if (line.includes("PrepareForSleep") && /\(\s*false\s*,?\s*\)/.test(line)) {
      expectBooleanAfterMember = false;
      return;
    }
    // dbus-monitor: member line, then a following "boolean true" / "boolean false"
    if (
      line.includes("member=PrepareForSleep") ||
      (line.includes("PrepareForSleep") && line.includes("interface="))
    ) {
      expectBooleanAfterMember = true;
      return;
    }
    if (expectBooleanAfterMember) {
      const trimmed = line.trim();
      if (trimmed === "boolean true" || /^boolean\s+true\b/.test(trimmed)) {
        expectBooleanAfterMember = false;
        opts.onSleep();
        return;
      }
      if (trimmed === "boolean false" || /^boolean\s+false\b/.test(trimmed)) {
        expectBooleanAfterMember = false;
        return;
      }
    }
  };

  const onStdout = (chunk: Buffer | string): void => {
    if (stopped) return;
    lineBuf += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    if (lineBuf.length > MAX_LINE_BUF) {
      lineBuf = lineBuf.slice(-MAX_LINE_BUF);
    }
    let nl: number;
    while ((nl = lineBuf.indexOf("\n")) >= 0) {
      const line = lineBuf.slice(0, nl);
      lineBuf = lineBuf.slice(nl + 1);
      handleLine(line);
    }
  };

  const scheduleRestart = (): void => {
    if (stopped) return;
    if (restartCount >= RESTART_BACKOFF_MS.length) {
      log("sleep lock: monitor exited too many times — giving up");
      return;
    }
    const delay = RESTART_BACKOFF_MS[restartCount]!;
    restartCount += 1;
    restartTimer = setTimeout(() => {
      restartTimer = null;
      startChild();
    }, delay);
    restartTimer.unref?.();
  };

  const startChild = (): void => {
    if (stopped) return;
    lineBuf = "";
    expectBooleanAfterMember = false;

    let cmd: string;
    let args: readonly string[];
    if (existsSync(GDBUS)) {
      cmd = GDBUS;
      args = GDBUS_ARGS;
    } else if (existsSync(DBUS_MONITOR)) {
      cmd = DBUS_MONITOR;
      args = DBUS_MONITOR_ARGS;
    } else {
      noteUnavailable("neither /usr/bin/gdbus nor /usr/bin/dbus-monitor found");
      return;
    }

    try {
      child = spawnFn(cmd, args, { stdio: ["ignore", "pipe", "ignore"] });
    } catch (e) {
      noteUnavailable(e instanceof Error ? e.message : String(e));
      return;
    }

    if (typeof child.stdout.setEncoding === "function") {
      child.stdout.setEncoding("utf8");
    }
    child.stdout.on("data", onStdout);
    child.on("error", (e) => {
      if (stopped) return;
      noteUnavailable(e instanceof Error ? e.message : String(e));
      killChild();
    });
    child.on("exit", () => {
      if (stopped) return;
      child = null;
      scheduleRestart();
    });
  };

  if (platform !== "linux") {
    // Non-Linux: silent no-op (no log spam on macOS test/dev runs).
    return { stop };
  }

  startChild();
  return { stop };
}
