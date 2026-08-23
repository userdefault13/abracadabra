<script lang="ts">
  import { getProjects, createProject, type VarInfo } from "./lib/api";
  import ProjectView from "./lib/ProjectView.svelte";
  import ConnectionsPanel from "./lib/ConnectionsPanel.svelte";
  import GrantsPanel from "./lib/GrantsPanel.svelte";

  let projects = $state<Record<string, Record<string, VarInfo>>>({});
  let route = $state(location.hash || "#/");
  let toast = $state<{ text: string; kind: "ok" | "error" } | null>(null);
  let newProjectName = $state("");
  let creating = $state(false);

  export function showToast(text: string, kind: "ok" | "error" = "ok") {
    toast = { text, kind };
    setTimeout(() => (toast = null), 5000);
  }

  async function refresh() {
    try {
      projects = (await getProjects()).projects;
    } catch (e) {
      showToast(String((e as Error).message), "error");
    }
  }
  refresh();
  // poll lightly so grants panel stays fresh
  const timer = setInterval(refresh, 15000);

  window.addEventListener("hashchange", () => (route = location.hash));

  async function addProject() {
    const name = newProjectName.trim();
    if (!name || creating) return;
    creating = true;
    try {
      await createProject(name);
      await refresh();
      showToast(`project "${name}" created`);
      location.hash = `#/project/${name}`;
      newProjectName = "";
    } catch (e) {
      showToast((e as Error).message, "error");
    } finally {
      creating = false;
    }
  }
</script>

<aside>
  <div class="brand">✦ abracadabra</div>

  <div class="new-project">
    <input
      type="text"
      placeholder="new project…"
      bind:value={newProjectName}
      onkeydown={(e) => e.key === "Enter" && addProject()}
    />
    <button class="primary" disabled={creating} onclick={addProject}>+</button>
  </div>

  <nav>
    {#each Object.keys(projects).sort() as name}
      <a href={"#/project/" + name} class:selected={route === "#/project/" + name}>
        {name}
        <span class="count">{Object.keys(projects[name]).length}</span>
      </a>
    {/each}
  </nav>

  <div class="spacer" />

  <nav class="secondary">
    <a href="#/connections" class:selected={route === "#/connections"}>Connections</a>
    <a href="#/grants" class:selected={route === "#/grants"}>Grants</a>
  </nav>
  <div class="footer">local · loopback only</div>
</aside>

<main>
  {#if route.startsWith("#/project/")}
    {@const name = decodeURIComponent(route.slice("#/project/".length))}
    {#if projects[name]}
      <ProjectView
        name={name}
        vars={projects[name]}
        onChanged={refresh}
        onDeleted={() => {
          location.hash = "#/";
          refresh();
        }}
      />
    {:else}
      <p class="dim">loading…</p>
    {/if}
  {:else if route === "#/connections"}
    <ConnectionsPanel onToast={showToast} />
  {:else if route === "#/grants"}
    <GrantsPanel />
  {:else}
    <div class="welcome">
      <h1>✦ abracadabra</h1>
      <p>Select a project from the sidebar, or create one above.</p>
      <p class="dim">
        Sensitive actions (reveal · edit · delete · create) pop a Touch ID prompt.
      </p>
    </div>
  {/if}
</main>

{#if toast}
  <div class="toast {toast.kind}">{toast.text}</div>
{/if}

<style>
  aside {
    width: 240px;
    min-width: 240px;
    background: var(--bg2);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    padding: 16px 12px;
  }
  .brand {
    font-weight: bold;
    color: var(--accent);
    margin-bottom: 16px;
    padding-left: 4px;
  }
  .new-project {
    display: flex;
    gap: 6px;
    margin-bottom: 12px;
  }
  .new-project input {
    flex: 1;
    min-width: 0;
  }
  nav {
    display: flex;
    flex-direction: column;
    gap: 2px;
    overflow-y: auto;
  }
  a {
    display: flex;
    justify-content: space-between;
    align-items: center;
    color: var(--text);
    text-decoration: none;
    padding: 7px 10px;
    border-radius: 6px;
  }
  a:hover {
    background: var(--bg3);
  }
  a.selected {
    background: rgba(210, 77, 240, 0.15);
    color: var(--accent);
  }
  .count {
    color: var(--dim);
    font-size: 12px;
  }
  .spacer {
    flex: 1;
  }
  .secondary a {
    color: var(--dim);
  }
  .footer {
    margin-top: 10px;
    color: var(--dim);
    font-size: 11px;
    padding-left: 4px;
  }
  main {
    flex: 1;
    padding: 28px 36px;
    max-width: 900px;
  }
  .welcome h1 {
    color: var(--accent);
  }
  .dim {
    color: var(--dim);
  }
</style>
