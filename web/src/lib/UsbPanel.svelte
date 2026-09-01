<script lang="ts">
  import {
    listUsb,
    usbBackup,
    usbSync,
    type UsbVolume,
    type UsbConflict,
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

  async function refresh() {
    try {
      volumes = (await listUsb()).volumes;
      if (!selected && volumes.length > 0) selected = volumes[0].mount;
      error = "";
    } catch (e) {
      error = (e as Error).message;
    }
  }
  let error = $state("");

  refresh();

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
        r.changed
          ? `synced — USB refreshed (${r.file})`
          : "already in sync",
      );
      await refresh();
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
  Back up the vault to a USB drive, or sync two computers through it. The bundle is
  passphrase-encrypted and carries the master key — treat the passphrase like the vault itself.
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
  <p class="dim">Values are masked here; reveal them via the project view if needed.</p>
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
  .refresh {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font-size: 12px;
    text-decoration: underline;
  }
</style>
