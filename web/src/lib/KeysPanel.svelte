<script lang="ts">
  import {
    listApiKeys,
    createApiKey,
    revokeApiKey,
    getProjects,
    type ApiKeyInfo,
  } from "./api";

  let { onToast }: { onToast: (text: string, kind?: "ok" | "error") => void } = $props();

  let keys = $state<ApiKeyInfo[]>([]);
  let projects = $state<string[]>([]);
  let busy = $state("");

  // create form
  let name = $state("");
  let scopeText = $state(""); // empty = all projects
  let expiresInDays = $state(0);
  let justCreated = $state<{ fullKey: string; name: string } | null>(null);
  let copied = $state(false);
  let error = $state("");

  async function refresh() {
    try {
      keys = (await listApiKeys()).keys;
      error = "";
    } catch (e) {
      error = (e as Error).message;
    }
  }
  refresh();
  getProjects()
    .then((r) => (projects = Object.keys(r.projects).sort()))
    .catch(() => {});

  async function create() {
    busy = "create";
    copied = false;
    try {
      const projectsList = scopeText
        .split(",")
        .map((p) => p.trim())
        .filter(Boolean);
      const r = await createApiKey({
        name,
        projects: projectsList.length > 0 ? projectsList : undefined,
        expiresInDays: expiresInDays > 0 ? expiresInDays : undefined,
      });
      justCreated = { fullKey: r.fullKey, name };
      name = "";
      scopeText = "";
      expiresInDays = 0;
      await refresh();
      onToast(`API key "${justCreated.name}" created`);
    } catch (e) {
      onToast((e as Error).message, "error");
    } finally {
      busy = "";
    }
  }

  async function copyKey() {
    if (!justCreated) return;
    await navigator.clipboard.writeText(justCreated.fullKey);
    copied = true;
  }

  async function revoke(k: ApiKeyInfo) {
    busy = k.id;
    try {
      await revokeApiKey(k.id);
      onToast(`revoked "${k.name}"`);
      await refresh();
    } catch (e) {
      onToast((e as Error).message, "error");
    } finally {
      busy = "";
    }
  }

  const fmtDate = (t?: number) => (t ? new Date(t).toLocaleDateString() : "—");
</script>

<h2 class="panel-title">API Keys</h2>
<p class="dim">
  Bearer tokens for <code>POST /secret</code> — issue one per AI agent or script so it can pull
  project vars without a Touch ID prompt each time. Keys are scoped to specific projects and only
  a hash is stored; the full key is shown once at creation.
</p>

<div class="create">
  <input placeholder="key name (e.g. opencode-agent)" bind:value={name} />
  <input placeholder="project scope, comma-separated (empty = all)" bind:value={scopeText} />
  <label class="exp">
    expires in
    <input type="number" min="0" bind:value={expiresInDays} /> days (0 = never)
  </label>
  <button class="primary" disabled={busy !== "" || !name.trim()} onclick={create}>
    {busy === "create" ? "approve Touch ID…" : "Issue key"}
  </button>
</div>

{#if justCreated}
  <div class="new-key">
    <p><b>{justCreated.name}</b> — copy this now, it will not be shown again:</p>
    <div class="row">
      <code class="full">{justCreated.fullKey}</code>
      <button onclick={copyKey}>{copied ? "copied ✓" : "copy"}</button>
    </div>
    <pre class="usage">curl -X POST http://127.0.0.1:7331/secret \
  -H "Authorization: Bearer &lt;key&gt;" \
  -H "Content-Type: application/json" \
  -d '&#123;"project": "myproj", "keys": ["MY_API_KEY"]&#125;'</pre>
    <button class="link" onclick={() => (justCreated = null)}>dismiss</button>
  </div>
{/if}

<table>
  <thead>
    <tr><th>key</th><th>name</th><th>scope</th><th>created</th><th>expires</th><th></th></tr>
  </thead>
  <tbody>
    {#each keys.sort((a, b) => a.createdAt - b.createdAt) as k (k.id)}
      <tr>
        <td class="mono">{k.prefix}…</td>
        <td>{k.name}</td>
        <td class="dim">{k.projects === null ? "all projects" : k.projects.join(", ")}</td>
        <td class="dim">{fmtDate(k.createdAt)}</td>
        <td class="dim">{fmtDate(k.expiresAt)}</td>
        <td>
          <button class="danger" disabled={busy === k.id} onclick={() => revoke(k)}>
            {busy === k.id ? "approve…" : "revoke"}
          </button>
        </td>
      </tr>
    {/each}
    {#if keys.length === 0}
      <tr><td colspan="6" class="dim">no API keys yet</td></tr>
    {/if}
  </tbody>
</table>

<p class="dim hint">
  Available projects: {projects.length > 0 ? projects.join(", ") : "(none yet)"} ·
  CLI equivalents: <code>abra keys new|ls|rm</code>
</p>

{#if error}<p class="error">{error}</p>{/if}

<style>
  .dim {
    color: var(--dim);
    font-size: 12px;
  }
  .mono {
    font-family: monospace;
  }
  .create {
    display: flex;
    flex-direction: column;
    gap: 8px;
    max-width: 480px;
    margin: 16px 0;
  }
  .create input[type="number"] {
    width: 70px;
  }
  .exp {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--dim);
    font-size: 12px;
  }
  .new-key {
    border: 1px solid var(--yellow, #e5c07b);
    border-radius: 10px;
    padding: 14px 16px;
    margin-bottom: 18px;
    max-width: 720px;
    background: rgba(229, 192, 123, 0.06);
  }
  .new-key p {
    margin: 0 0 8px;
    font-size: 13px;
  }
  .row {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .full {
    font-family: monospace;
    word-break: break-all;
    font-size: 12px;
    background: var(--bg3, rgba(255, 255, 255, 0.05));
    padding: 8px 10px;
    border-radius: 6px;
    flex: 1;
  }
  .usage {
    font-size: 11px;
    color: var(--dim);
    overflow-x: auto;
    margin: 10px 0 6px;
  }
  .link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font-size: 12px;
    text-decoration: underline;
  }
  .hint {
    margin-top: 12px;
  }
  .error {
    color: var(--red);
    font-size: 12px;
  }
</style>
