<script lang="ts">
  import {
    listUsb,
    usbBackup,
    usbSync,
    usbLanHostStart,
    usbLanHostStop,
    usbLanHostStatus,
    usbLanPeers,
    usbLanSync,
    type UsbVolume,
    type UsbConflict,
    type LanHostStatus,
    type LanPeer,
  } from "./api";

  let { onToast }: { onToast: (text: string, kind?: "ok" | "error") => void } = $props();

  let volumes = $state<UsbVolume[]>([]);
  let selected = $state("");
  let passphrase = $state("");
  let busy = $state("");
  let previewReport = $state<string[]>([]);
  let conflicts = $state<UsbConflict[]>([]);
  let needsResolution = $state(false);
  let force = $state<"ours" | "theirs">("theirs");
  let lastBackupFile = $state("");
  let error = $state("");

  // LAN
  let lanHost = $state<LanHostStatus | null>(null);
  let peers = $state<LanPeer[]>([]);
  let joinHost = $state("");
  let joinPin = $state("");
  let joinFingerprint = $state("");
  let lanPreviewReport = $state<string[]>([]);
  let lanConflicts = $state<UsbConflict[]>([]);
  let lanNeedsResolution = $state(false);
  let lanForce = $state<"ours" | "theirs">("theirs");

  async function refresh() {
    try {
      volumes = (await listUsb()).volumes;
      if (!selected && volumes.length > 0) selected = volumes[0].mount;
      error = "";
      const st = await usbLanHostStatus();
      lanHost = st.host;
    } catch (e) {
      error = (e as Error).message;
    }
  }

  refresh();
  const poll = setInterval(() => {
    void usbLanHostStatus()
      .then((st) => {
        lanHost = st.host;
      })
      .catch(() => {});
  }, 5000);
  $effect(() => () => clearInterval(poll));

  function target(): string | undefined {
    return selected || undefined;
  }

  async function backup() {
    if (!selected) return;
    busy = "backup";
    try {
      const { file } = await usbBackup(selected, passphrase);
      lastBackupFile = file;
      onToast(`backup written: ${file}`);
      await refresh();
    } catch (e) {
      onToast((e as Error).message, "error");
    } finally {
      busy = "";
    }
  }

  async function check() {
    busy = "check";
    try {
      const r = await usbSync({ target: target(), passphrase, apply: false });
      previewReport = r.report ?? [];
      conflicts = r.conflicts ?? [];
      needsResolution = r.needsResolution ?? false;
      if (!needsResolution && previewReport.length === 0) onToast("already in sync");
    } catch (e) {
      onToast((e as Error).message, "error");
    } finally {
      busy = "";
    }
  }

  async function apply() {
    busy = "apply";
    try {
      const r = await usbSync({
        target: target(),
        passphrase,
        apply: true,
        force: conflicts.length > 0 ? force : undefined,
      });
      previewReport = [];
      conflicts = [];
      needsResolution = false;
      onToast(
        r.changed ? `synced — USB refreshed (${r.file})` : "already in sync",
      );
      await refresh();
    } catch (e) {
      onToast((e as Error).message, "error");
    } finally {
      busy = "";
    }
  }

  async function startHost() {
    busy = "host-start";
    try {
      lanHost = await usbLanHostStart({ ttl: 600 });
      onToast(`LAN host started — PIN ${lanHost.pin}`);
    } catch (e) {
      onToast((e as Error).message, "error");
    } finally {
      busy = "";
    }
  }

  async function stopHost() {
    busy = "host-stop";
    try {
      await usbLanHostStop();
      lanHost = null;
      onToast("LAN host stopped");
    } catch (e) {
      onToast((e as Error).message, "error");
    } finally {
      busy = "";
    }
  }

  async function refreshPeers() {
    busy = "peers";
    try {
      peers = (await usbLanPeers()).peers;
      if (peers.length === 0) onToast("no LAN peers found");
    } catch (e) {
      onToast((e as Error).message, "error");
    } finally {
      busy = "";
    }
  }

  function pickPeer(p: LanPeer) {
    joinHost = `${p.host}:${p.port}`;
    joinFingerprint = p.fingerprint ?? "";
  }

  async function lanCheck() {
    if (!joinHost || !joinPin) return;
    busy = "lan-check";
    try {
      const r = await usbLanSync({
        host: joinHost,
        pin: joinPin,
        fingerprint: joinFingerprint || undefined,
        apply: false,
      });
      lanPreviewReport = r.report ?? [];
      lanConflicts = r.conflicts ?? [];
      lanNeedsResolution = r.needsResolution ?? false;
      if (!lanNeedsResolution && lanPreviewReport.length === 0) onToast("already in sync");
    } catch (e) {
      onToast((e as Error).message, "error");
    } finally {
      busy = "";
    }
  }

  async function lanApply() {
    if (!joinHost || !joinPin) return;
    busy = "lan-apply";
    try {
      const r = await usbLanSync({
        host: joinHost,
        pin: joinPin,
        fingerprint: joinFingerprint || undefined,
        apply: true,
        force: lanConflicts.length > 0 ? lanForce : undefined,
      });
      lanPreviewReport = [];
      lanConflicts = [];
      lanNeedsResolution = false;
      onToast(r.changed ? "LAN sync complete" : "already in sync");
    } catch (e) {
      onToast((e as Error).message, "error");
    } finally {
      busy = "";
    }
  }

  const fmtDate = (t?: number) => (t ? new Date(t).toLocaleString() : "—");
</script>

<h2 class="panel-title">USB Backup &amp; Sync</h2>
<p class="dim">
  Back up the vault to a USB drive, or sync two computers through it or over the local
  network. USB bundles are passphrase-encrypted; LAN sessions use a short-lived PIN and TLS.
</p>

{#if volumes.length === 0}
  <p class="dim">No mounted volumes found. Plug in a USB stick and refresh.</p>
{:else}
  <div class="controls">
    <label>
      volume
      <select bind:value={selected} onchange={() => { previewReport = []; conflicts = []; needsResolution = false; }}>
        {#each volumes as v (v.mount)}
          <option value={v.mount}>
            {v.name}{v.backupAt ? ` — backup ${fmtDate(v.backupAt)}` : ""}
          </option>
        {/each}
      </select>
    </label>
    <label>
      passphrase
      <input type="password" placeholder="bundle passphrase" bind:value={passphrase} />
    </label>
  </div>

  <div class="actions">
    <button class="primary" disabled={busy !== "" || !passphrase} onclick={backup}>
      {busy === "backup" ? "waiting for Touch ID…" : "Back up now"}
    </button>
    <button disabled={busy !== "" || !passphrase} onclick={check}>
      {busy === "check" ? "checking…" : "Check for changes"}
    </button>
    {#if previewReport.length > 0 || conflicts.length > 0}
      <button class="primary" disabled={busy !== "" || (conflicts.length > 0 && !passphrase)} onclick={apply}>
        {busy === "apply" ? "syncing…" : "Apply sync"}
      </button>
    {/if}
  </div>
{/if}

{#if needsResolution}
  <p class="warn">
    {conflicts.length} conflict(s) — pick a resolution before applying:
    <label><input type="radio" bind:group={force} value="theirs" /> keep USB copy</label>
    <label><input type="radio" bind:group={force} value="ours" /> keep this machine</label>
  </p>
  <table>
    <thead>
      <tr><th>project / var</th><th>this machine</th><th>USB copy</th><th>newest</th></tr>
    </thead>
    <tbody>
      {#each conflicts as c (`${c.scope}/${c.key}`)}
        <tr>
          <td>{c.scope}/{c.key}</td>
          <td class="mono">{c.ours}</td>
          <td class="mono">{c.theirs}</td>
          <td>{c.newest}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

{#if previewReport.length > 0}
  <h3>pending changes</h3>
  <ul class="report">
    {#each previewReport as line}
      <li>{line}</li>
    {/each}
  </ul>
{/if}

{#if lastBackupFile}
  <p class="dim ok">✓ latest backup: {lastBackupFile}</p>
{/if}

<button class="link refresh" onclick={refresh}>refresh volumes</button>

<hr class="sep" />

<h3>Network sync</h3>
<p class="dim">Host a short-lived TLS session, or join another Mac on the LAN with its PIN.</p>

<div class="actions">
  {#if lanHost}
    <button disabled={busy !== ""} onclick={stopHost}>
      {busy === "host-stop" ? "stopping…" : "Stop host"}
    </button>
  {:else}
    <button class="primary" disabled={busy !== ""} onclick={startHost}>
      {busy === "host-start" ? "waiting for Touch ID…" : "Start LAN host"}
    </button>
  {/if}
  <button disabled={busy !== ""} onclick={refreshPeers}>
    {busy === "peers" ? "browsing…" : "Find peers"}
  </button>
</div>

{#if lanHost}
  <div class="lan-host">
    <p><span class="dim">PIN</span> <strong class="mono">{lanHost.pin}</strong></p>
    <p><span class="dim">fingerprint</span> <span class="mono">{lanHost.fingerprint}</span></p>
    <p><span class="dim">expires</span> {fmtDate(lanHost.expiresAt)}</p>
    {#each lanHost.addresses as addr}
      <p class="mono">{addr}:{lanHost.port}</p>
    {/each}
  </div>
{/if}

{#if peers.length > 0}
  <ul class="peers">
    {#each peers as p (`${p.host}:${p.port}`)}
      <li>
        <button class="link" onclick={() => pickPeer(p)}>
          {p.hostname || p.name} — {p.host}:{p.port}
        </button>
      </li>
    {/each}
  </ul>
{/if}

<div class="controls">
  <label>
    host:port
    <input type="text" placeholder="192.168.1.10:7332" bind:value={joinHost} />
  </label>
  <label>
    PIN
    <input type="password" placeholder="6-digit PIN" maxlength="6" bind:value={joinPin} />
  </label>
  <label>
    fingerprint (optional)
    <input type="text" placeholder="AA:BB:…" bind:value={joinFingerprint} />
  </label>
</div>

<div class="actions">
  <button disabled={busy !== "" || !joinHost || joinPin.length !== 6} onclick={lanCheck}>
    {busy === "lan-check" ? "checking…" : "Check LAN sync"}
  </button>
  {#if lanPreviewReport.length > 0 || lanConflicts.length > 0}
    <button class="primary" disabled={busy !== ""} onclick={lanApply}>
      {busy === "lan-apply" ? "syncing…" : "Apply LAN sync"}
    </button>
  {/if}
</div>

{#if lanNeedsResolution}
  <p class="warn">
    {lanConflicts.length} conflict(s):
    <label><input type="radio" bind:group={lanForce} value="theirs" /> keep peer</label>
    <label><input type="radio" bind:group={lanForce} value="ours" /> keep this machine</label>
  </p>
{/if}

{#if lanPreviewReport.length > 0}
  <ul class="report">
    {#each lanPreviewReport as line}
      <li>{line}</li>
    {/each}
  </ul>
{/if}

{#if error}<p class="error">{error}</p>{/if}

<style>
  .dim {
    color: var(--dim);
    font-size: 12px;
  }
  .controls {
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin: 18px 0;
    max-width: 480px;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 12px;
    color: var(--dim);
  }
  select,
  input {
    color: var(--text);
  }
  .actions {
    display: flex;
    gap: 8px;
    margin-bottom: 18px;
    flex-wrap: wrap;
  }
  h3 {
    margin: 18px 0 6px;
    font-size: 13px;
  }
  ul.report {
    font-size: 12px;
    line-height: 1.7;
    padding-left: 18px;
  }
  .warn {
    color: var(--yellow);
    font-size: 12px;
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }
  .mono {
    font-family: monospace;
  }
  .error {
    color: var(--red);
    font-size: 12px;
  }
  .ok {
    color: var(--green, #7bd88f);
  }
  .refresh,
  .link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font-size: 12px;
    text-decoration: underline;
  }
  .sep {
    border: none;
    border-top: 1px solid var(--border, #333);
    margin: 28px 0 18px;
  }
  .lan-host {
    font-size: 13px;
    line-height: 1.6;
    margin-bottom: 16px;
  }
  .peers {
    list-style: none;
    padding: 0;
    margin: 0 0 16px;
    font-size: 12px;
  }
</style>
