#!/usr/bin/env node
// Demo "web dapp": asks abracadabra for a secret over the local API.
// The user sees a Touch ID dialog naming this process before the value arrives;
// with --ttl N, one approval grants silent access for that app+project for N seconds.
//
// Usage: node demo/dapp-client.mjs [project] [key] [ttlSeconds]

const project = process.argv[2] ?? "myproj";
const key = process.argv[3] ?? "CLOUDFLARE_API_TOKEN";
const ttl = Number(process.argv[4] ?? 0) || undefined;

const res = await fetch("http://127.0.0.1:7331/secret", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ project, keys: [key], ...(ttl ? { ttl } : {}) }),
});

if (!res.ok) {
  const body = await res.json().catch(() => ({}));
  console.error(`✗ abracadabra said no (${res.status}): ${body.error ?? ""}`);
  process.exit(1);
}

const values = await res.json();
console.log(`✓ dapp received ${key} (length ${values[key].length})`);
