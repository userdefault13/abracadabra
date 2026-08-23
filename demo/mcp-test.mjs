#!/usr/bin/env node
// MCP stdio handshake test: initialize → tools/list → tools/call
import { spawn } from "node:child_process";

const child = spawn("node", ["dist/index.js", "mcp"], {
  env: { ...process.env, ABRA_SKIP_BIOMETRICS: "1" },
  stdio: ["pipe", "pipe", "inherit"],
});

let buf = "";
const pending = new Map();
child.stdout.on("data", (d) => {
  buf += d.toString();
  let idx;
  while ((idx = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (!line) continue;
    try {
      const msg = JSON.parse(line);
      if (msg.id !== undefined && pending.has(msg.id)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      }
    } catch {}
  }
});

function send(obj) {
  child.stdin.write(JSON.stringify(obj) + "\n");
}
function request(id, method, params) {
  return new Promise((resolve) => {
    pending.set(id, resolve);
    send({ jsonrpc: "2.0", id, method, params });
  });
}

const init = await request(1, "initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "abra-test-client", version: "0.0.1" },
});
console.log("── initialize ok:", init.result?.serverInfo?.name ?? init);
send({ jsonrpc: "2.0", method: "notifications/initialized" });

const tools = await request(2, "tools/list", {});
console.log("── tools:", tools.result.tools.map((t) => t.name).join(", "));

const projects = await request(3, "tools/call", {
  name: "list_projects",
  arguments: {},
});
const pj = JSON.parse(projects.result.content[0].text);
console.log("── list_projects →", Object.keys(pj.projects));

const secrets = await request(4, "tools/call", {
  name: "get_secrets",
  arguments: { project: "ai-cron-site", keys: ["EVM_ADDRESS"], requestedBy: "abra-test-agent" },
});
const sj = JSON.parse(secrets.result.content[0].text);
console.log("── get_secrets approved:", sj.approved, "| vars keys:", Object.keys(sj.vars));
console.log("── address matches vault:", sj.vars.EVM_ADDRESS);

const denied = await request(5, "tools/call", {
  name: "get_secrets",
  arguments: { project: "ai-cron-site", keys: ["NOPE"] },
});
console.log("── missing key isError:", denied.result.isError, "|", JSON.parse(denied.result.content[0].text).error);

child.kill();
process.exit(0);
