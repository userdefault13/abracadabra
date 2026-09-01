import { applyUpdate, checkForUpdate, resolveLatestRelease } from "../core/update.js";

export async function updateCommand(opts: { check?: boolean; apply?: boolean; force?: boolean }, currentVersion: string): Promise<void> {
  if (opts.check) {
    const latest = await resolveLatestRelease();
    if (!latest) {
      console.log("could not reach update server (CDN or npm registry)");
      return;
    }
    console.log(`current: ${currentVersion}`);
    console.log(`latest:  ${latest.manifest.version} (${latest.source})`);
    if (latest.manifest.url) console.log(`url:     ${latest.manifest.url}`);
    return;
  }

  const pending = await checkForUpdate(currentVersion, { force: opts.force ?? true });
  if (!pending) {
    console.log(`✓ abracadabra ${currentVersion} is up to date`);
    return;
  }

  console.log(`update available: ${pending.currentVersion} → ${pending.latestVersion}`);
  if (opts.apply) {
    const ok = await applyUpdate(pending.manifest, pending.source);
    process.exit(ok ? 0 : 1);
  }

  console.log("run: abra update --apply");
}
