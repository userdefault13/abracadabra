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
