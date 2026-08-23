<script lang="ts">
  import { deleteConnection, getConnections } from "./api";

  let {
    onToast,
  }: {
    onToast: (text: string, kind?: "ok" | "error") => void;
  } = $props();

  let connections = $state<
    { provider: string; label?: string; createdAt: number; credentials: string[] }[]
  >([]);
  let busy = $state("");

  async function refresh() {
    try {
      connections = (await getConnections()).connections;
    } catch (e) {
      onToast((e as Error).message, "error");
    }
  }
  refresh();

  async function disconnect(provider: string) {
    busy = provider;
    try {
      await deleteConnection(provider);
      onToast(`disconnected ${provider}`);
      await refresh();
    } catch (e) {
      onToast((e as Error).message, "error");
    } finally {
      busy = "";
    }
  }
</script>

<h2 class="panel-title">Connections</h2>
<p class="dim">
  Provider accounts linked via <code>abra connect &lt;provider&gt;</code>. Disconnecting requires
  Touch ID. New connections are added from the terminal.
</p>

<table>
  <thead>
    <tr><th>provider</th><th>label</th><th>credentials</th><th>connected</th><th></th></tr>
  </thead>
  <tbody>
    {#each connections.sort((a, b) => a.provider.localeCompare(b.provider)) as c (c.provider)}
      <tr>
        <td>{c.provider}</td>
        <td class="dim">{c.label ?? "—"}</td>
        <td>{c.credentials.join(", ")}</td>
        <td class="dim">{new Date(c.createdAt).toLocaleDateString()}</td>
        <td>
          <button class="danger" disabled={busy === c.provider} onclick={() => disconnect(c.provider)}>
            {busy === c.provider ? "approve…" : "disconnect"}
          </button>
        </td>
      </tr>
    {/each}
    {#if connections.length === 0}
      <tr><td colspan="5" class="dim">no connections — try: abra connect cdp | cloudflare | vercel</td></tr>
    {/if}
  </tbody>
</table>

<style>
  .dim {
    color: var(--dim);
    font-size: 12px;
  }
  td button {
    padding: 3px 8px;
  }
</style>
