<script lang="ts">
  import { getGrants, revokeGrants } from "./api";

  let grants = $state<{ appId: string; project: string; remainingSec: number }[]>([]);
  let revoking = $state(false);
  let error = $state("");

  async function refresh() {
    try {
      grants = (await getGrants()).grants;
      error = "";
    } catch (e) {
      error = (e as Error).message;
    }
  }
  refresh();
  const timer = setInterval(refresh, 10000);

  async function revokeAll() {
    revoking = true;
    try {
      const { revoked } = await revokeGrants();
      await refresh();
      if (revoked > 0) setTimeout(() => {}, 0);
    } finally {
      revoking = false;
    }
  }
</script>

<h2 class="panel-title">Session Grants</h2>
<p class="dim">
  Apps currently holding silent access via Touch ID session grants (issued through
  <code>POST /secret</code> with <code>ttl</code>). In-memory only — restarting
  <code>abra serve</code> clears them.
</p>

<table>
  <thead>
    <tr><th>app</th><th>project</th><th>expires in</th></tr>
  </thead>
  <tbody>
    {#each grants.sort((a, b) => a.project.localeCompare(b.project)) as g (g.appId + g.project)}
      <tr>
        <td class="app">{g.appId}</td>
        <td>{g.project}</td>
        <td class="ttl">{Math.floor(g.remainingSec / 60)}m {g.remainingSec % 60}s</td>
      </tr>
    {/each}
    {#if grants.length === 0}
      <tr><td colspan="3" class="dim">no active grants</td></tr>
    {/if}
  </tbody>
</table>

{#if grants.length > 0}
  <div class="footer-row">
    <button class="danger" disabled={revoking} onclick={revokeAll}>
      {revoking ? "revoking…" : "revoke all"}
    </button>
  </div>
{/if}

{#if error}<p class="error">{error}</p>{/if}

<style>
  .dim {
    color: var(--dim);
    font-size: 12px;
  }
  .app {
    max-width: 480px;
    word-break: break-all;
    color: var(--dim);
  }
  .ttl {
    color: var(--yellow);
  }
  .footer-row {
    margin-top: 16px;
  }
  .error {
    color: var(--red);
  }
</style>
