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

export async function promptHidden(question: string): Promise<string> {
  const headless = headlessPassphrase();
  if (headless) return headless;
  const rl = readline.createInterface({ input: process.stdin, output: undefined });
  process.stdout.write(question);
  return new Promise((resolve) => {
    let value = "";
    const onKeypress = (ch: string, key: { name?: string; ctrl?: boolean; meta?: boolean }) => {
      if (key?.ctrl && key.name === "c") {
        cleanup();
        process.stdout.write("\n");
        process.exit(130);
      }
      if (key?.name === "return" || key?.name === "enter") {
        cleanup();
        process.stdout.write("\n");
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
      process.stdin.removeListener("keypress", onKeypress);
      rl.close();
      if (process.stdin.isTTY && process.stdin.setRawMode) {
        process.stdin.setRawMode(false);
      }
      process.stdin.pause();
    }
    if (process.stdin.isTTY && process.stdin.setRawMode) {
      process.stdin.setRawMode(true);
    }
    readline.emitKeypressEvents(process.stdin, rl);
    process.stdin.resume();
    process.stdin.on("keypress", onKeypress);
  });
}
