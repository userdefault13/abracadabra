/**
 * Test-only harness for src/sync/pair.loopback.test.ts: runs the real pairing
 * listener (real vault I/O in its own ABRA_DIR) on 127.0.0.1:0 and reports to
 * the parent as JSON lines on stdout. The safety-code answer comes from argv
 * here — production has no flag or env var that skips the TTY confirmation.
 *
 *   node --import tsx test/fixtures/sync-pair-listener.ts <yes|no>
 */
import { defaultSyncDeps } from "../../src/commands/sync.js";
import { pairListen } from "../../src/sync/pair.js";

const answer = process.argv[2];
const emit = (o: unknown) => process.stdout.write(`${JSON.stringify(o)}\n`);

if (answer !== "yes" && answer !== "no") {
  emit({ type: "done", ok: false, error: "usage: sync-pair-listener.ts <yes|no>" });
  process.exit(2);
}

try {
  const result = await pairListen(
    {
      port: 0,
      bind: "127.0.0.1",
      ttlMs: 60_000,
      role: "source",
      onListening: (info) =>
        emit({
          type: "listening",
          port: info.port,
          pin: info.pin,
          tlsFingerprint: info.tlsFingerprint,
          identityFingerprint: info.identityFingerprint,
        }),
    },
    {
      ...defaultSyncDeps(),
      confirm: async () => answer === "yes",
      log: (line) => process.stderr.write(`${line}\n`),
    },
  );
  emit({ type: "done", ok: true, safetyCode: result.safetyCode, peerId: result.peerId, peerSaved: result.peerSaved });
  process.exit(0);
} catch (err) {
  emit({ type: "done", ok: false, error: err instanceof Error ? err.message : String(err) });
  process.exit(1);
}
