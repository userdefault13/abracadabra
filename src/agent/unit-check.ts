import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Does an installed abra-agent systemd unit let `ss` open its sock_diag
 * (AF_NETLINK) socket? Without it every peer check fails and `abra unlock`
 * cannot share the key with the agent.
 *
 * Mirrors systemd's RestrictAddressFamilies= merge rules closely enough for a
 * diagnostic: allow-lists accumulate, an empty assignment resets, a `~` list
 * is a deny-list.
 */
export type AgentUnitNetlink =
  | { status: "ok" }
  | { status: "unrestricted" }
  | { status: "missing_netlink"; families: string[] };

export function checkUnitNetlink(unitTexts: string[]): AgentUnitNetlink {
  let allow: Set<string> | null = null;
  let deny: Set<string> | null = null;
  for (const text of unitTexts) {
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (line.startsWith("#") || line.startsWith(";")) continue;
      const m = /^RestrictAddressFamilies\s*=\s*(.*)$/.exec(line);
      if (!m) continue;
      const value = m[1].trim();
      if (!value) {
        allow = null;
        deny = null;
        continue;
      }
      if (value === "none") {
        allow = new Set();
        deny = null;
        continue;
      }
      if (value.startsWith("~")) {
        deny ??= new Set();
        for (const f of value.slice(1).split(/\s+/)) if (f) deny.add(f);
      } else {
        allow ??= new Set();
        for (const f of value.split(/\s+/)) if (f) allow.add(f);
      }
    }
  }
  if (allow) {
    return allow.has("AF_NETLINK")
      ? { status: "ok" }
      : { status: "missing_netlink", families: [...allow] };
  }
  if (deny?.has("AF_NETLINK")) {
    return { status: "missing_netlink", families: [`~${[...deny].join(" ")}`] };
  }
  return { status: "unrestricted" };
}

/** ~/.config/systemd/user/abra-agent.service + its *.conf drop-ins (sorted). */
export function readInstalledAgentUnit(
  configHome: string = process.env.XDG_CONFIG_HOME ||
    path.join(os.homedir(), ".config"),
): { path: string; texts: string[] } | null {
  const unitPath = path.join(configHome, "systemd", "user", "abra-agent.service");
  let main: string;
  try {
    main = fs.readFileSync(unitPath, "utf8");
  } catch {
    return null;
  }
  const texts = [main];
  const dropDir = `${unitPath}.d`;
  try {
    for (const f of fs.readdirSync(dropDir).filter((n) => n.endsWith(".conf")).sort()) {
      try {
        texts.push(fs.readFileSync(path.join(dropDir, f), "utf8"));
      } catch {
        /* unreadable drop-in → ignore */
      }
    }
  } catch {
    /* no drop-ins */
  }
  return { path: unitPath, texts };
}

/**
 * Collect Environment= assignments from unit + drop-in texts (later wins).
 * Supports `Environment=KEY=VAL` and `Environment="KEY=VAL" KEY2=VAL2`.
 */
export function parseUnitEnvironment(unitTexts: string[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const text of unitTexts) {
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (line.startsWith("#") || line.startsWith(";")) continue;
      const m = /^Environment\s*=\s*(.*)$/.exec(line);
      if (!m) continue;
      for (const pair of splitEnvironmentAssignments(m[1].trim())) {
        const eq = pair.indexOf("=");
        if (eq <= 0) continue;
        out.set(pair.slice(0, eq), pair.slice(eq + 1));
      }
    }
  }
  return out;
}

/** Split systemd Environment= value into KEY=VAL tokens (quoted-aware, simple). */
function splitEnvironmentAssignments(value: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (quote) {
      if (c === quote) quote = null;
      else cur += c;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      continue;
    }
    if (/\s/.test(c)) {
      if (cur) {
        out.push(cur);
        cur = "";
      }
      continue;
    }
    cur += c;
  }
  if (cur) out.push(cur);
  return out;
}

/**
 * Last ExecStart= from unit texts: `ExecStart=/path/node /path/server.js …`
 * Returns absolute node + first script arg when both look absolute.
 */
export function parseUnitExecStart(
  unitTexts: string[],
): { node: string; script: string } | null {
  let last: string | null = null;
  for (const text of unitTexts) {
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (line.startsWith("#") || line.startsWith(";")) continue;
      const m = /^ExecStart\s*=\s*(.*)$/.exec(line);
      if (m) last = m[1].trim();
    }
  }
  if (!last) return null;
  // Drop optional argv0 prefix `ExecStart=-/path` or `!/path`
  const cleaned = last.replace(/^[@:+-]+/, "");
  const parts = cleaned.split(/\s+/).filter(Boolean);
  if (parts.length < 2) return null;
  const node = parts[0];
  const script = parts[1];
  if (!path.isAbsolute(node) || !path.isAbsolute(script)) return null;
  return { node, script };
}
