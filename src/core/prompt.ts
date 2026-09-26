import fs from "node:fs";
import tty from "node:tty";
import readline from "node:readline";
import { headlessPassphrase } from "../platform/env.js";

export function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

export type TtyHandles = {
  input: NodeJS.ReadStream & {
    setRawMode?: (mode: boolean) => void;
    isTTY?: boolean;
  };
  output: NodeJS.WritableStream;
  close: () => void;
};

const NO_TERMINAL_MSG = "no terminal: use ssh -t";

/** Thrown when `/dev/tty` (or Windows stdin TTY fallback) cannot be opened. */
export class NoTerminalError extends Error {
  constructor(message = `abracadabra: ${NO_TERMINAL_MSG}`) {
    super(message);
    this.name = "NoTerminalError";
  }
}

export function isNoTerminalError(err: unknown): boolean {
  if (err instanceof NoTerminalError) return true;
  if (!(err instanceof Error)) return false;
  return err.message.includes(NO_TERMINAL_MSG);
}

function defaultOpenTty(): TtyHandles {
  // Prefer the controlling terminal so piped stdin cannot supply the passphrase.
  try {
    const fdIn = fs.openSync("/dev/tty", "r");
    const fdOut = fs.openSync("/dev/tty", "w");
    const input = new tty.ReadStream(fdIn);
    const output = new tty.WriteStream(fdOut);
    let closed = false;
    return {
      input,
      output,
      close: () => {
        if (closed) return;
        closed = true;
        try {
          input.destroy();
        } catch {
          /* ignore */
        }
        try {
          output.destroy();
        } catch {
          /* ignore */
        }
        // destroy() closes the fds; ignore EBADF if already closed.
        try {
          fs.closeSync(fdIn);
        } catch {
          /* ignore */
        }
        try {
          fs.closeSync(fdOut);
        } catch {
          /* ignore */
        }
      },
    };
  } catch {
    // Windows has no /dev/tty; interactive console may still use stdin raw mode.
    if (process.platform === "win32" && process.stdin.isTTY) {
      return {
        input: process.stdin,
        output: process.stderr,
        close: () => {
          /* stdin/stderr owned by process */
        },
      };
    }
    throw new NoTerminalError();
  }
}

let openTtyImpl: () => TtyHandles = defaultOpenTty;

/** Test hook — inject a fake tty (or null to restore). */
export function setOpenTtyForTests(fn: (() => TtyHandles) | null): void {
  openTtyImpl = fn ?? defaultOpenTty;
}

/**
 * Hidden passphrase / secret prompt.
 *
 * Reads from the controlling terminal (`/dev/tty`) with echo off — never from
 * stdin pipes, env, or argv. Prompt text is written to the tty (not stdout).
 *
 * On Windows without `/dev/tty`, falls back to stdin raw mode and writes the
 * prompt to `output` (default stderr) so MCP JSON-RPC on stdout stays clean.
 *
 * `ABRA_HEADLESS_PASSPHRASE` is honored only when CI skip flags are set
 * (`ABRA_SKIP_BIOMETRICS=1` or `ABRA_AUTH=none`) — see `headlessPassphrase()`.
 *
 * @param output Used only for the Windows stdin fallback (and legacy callers
 *   such as PasswordPromptAuth). Ignored when `/dev/tty` is available.
 */
export async function promptHidden(
  question: string,
  output: NodeJS.WritableStream = process.stderr,
): Promise<string> {
  const headless = headlessPassphrase();
  if (headless) return headless;

  // Open tty BEFORE writing any prompt text (no partial leak on open failure).
  let handles: TtyHandles;
  try {
    handles = openTtyImpl();
  } catch (err) {
    if (isNoTerminalError(err)) {
      throw err instanceof NoTerminalError ? err : new NoTerminalError();
    }
    throw new NoTerminalError();
  }

  const { input, close } = handles;
  // Prefer real tty output; on Windows fallback use caller-supplied stream.
  const out = handles.output ?? output;
  out.write(question);

  return new Promise((resolve, reject) => {
    let value = "";
    let cleaned = false;

    const onKeypress = (ch: string, key: { name?: string; ctrl?: boolean; meta?: boolean }) => {
      if (key?.ctrl && key.name === "c") {
        cleanup();
        try {
          out.write("\n");
        } catch {
          /* ignore */
        }
        process.exit(130);
      }
      if (key?.name === "return" || key?.name === "enter") {
        cleanup();
        try {
          out.write("\n");
        } catch {
          /* ignore */
        }
        resolve(value);
        return;
      }
      if (key?.name === "backspace") {
        value = value.slice(0, -1);
        return;
      }
      if (ch && !key?.ctrl && !key?.meta) value += ch;
    };

    function cleanup() {
      if (cleaned) return;
      cleaned = true;
      input.removeListener("keypress", onKeypress);
      if (input.isTTY && input.setRawMode) {
        try {
          input.setRawMode(false);
        } catch {
          /* ignore */
        }
      }
      try {
        input.pause();
      } catch {
        /* ignore */
      }
      close();
    }

    try {
      if (input.isTTY && input.setRawMode) {
        input.setRawMode(true);
      }
      readline.emitKeypressEvents(input);
      input.resume();
      input.on("keypress", onKeypress);
    } catch (err) {
      cleanup();
      reject(isNoTerminalError(err) ? (err instanceof Error ? err : new NoTerminalError()) : new NoTerminalError());
    }
  });
}
