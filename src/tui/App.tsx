import { Box, Text, useApp, useInput } from "ink";
import { useCallback, useEffect, useState } from "react";
import {
  loadVault,
  saveVault,
  type Vault,
} from "../core/vault.js";
import { authenticate } from "../auth/touchid.js";
import { ConfirmView, Header, InputView, SelectList } from "./components.js";
import type { InputRequest } from "./components.js";

type View =
  | { name: "loading" }
  | { name: "projects" }
  | { name: "vars"; project: string }
  | { name: "input"; request: InputRequest; returnTo: View }
  | { name: "confirm"; message: string; onConfirm: () => void | Promise<void>; returnTo: View };

export function App() {
  const { exit } = useApp();
  const [vault, setVault] = useState<Vault | null>(null);
  const [view, setView] = useState<View>({ name: "loading" });
  const [status, setStatus] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<{ project: string; key: string } | null>(null);

  useEffect(() => {
    loadVault()
      .then((v) => {
        setVault(v);
        setView({ name: "projects" });
      })
      .catch((err: unknown) => {
        console.error(`✗ ${err instanceof Error ? err.message : String(err)}`);
        exit();
      });
  }, [exit]);

  const mutate = useCallback(
    async (fn: (v: Vault) => void | Promise<void>, note?: string) => {
      if (!vault) return;
      const next: Vault = JSON.parse(JSON.stringify(vault));
      await fn(next);
      await saveVault(next);
      setVault(next);
      setStatus(note ?? null);
    },
    [vault],
  );

  const openInput = (request: InputRequest, returnTo: View) =>
    setView({ name: "input", request, returnTo });

  if (!vault || view.name === "loading") {
    return <Text dimColor>unlocking vault…</Text>;
  }

  if (view.name === "input") {
    return <InputView request={view.request} />;
  }

  if (view.name === "confirm") {
    return (
      <ConfirmView
        message={view.message}
        onConfirm={() => void view.onConfirm()}
        onCancel={() => setView(view.returnTo)}
      />
    );
  }

  if (view.name === "projects") {
    return (
      <ProjectsView
        vault={vault}
        status={status}
        onSelect={(name) => {
          setStatus(null);
          setView({ name: "vars", project: name });
        }}
        onNew={() =>
          openInput(
            {
              title: "New project name",
              onSubmit: async (value) => {
                const name = value.trim();
                if (!name) return;
                if (vault.projects[name]) {
                  setStatus(`project "${name}" already exists`);
                  setView({ name: "projects" });
                  return;
                }
                await mutate((v) => {
                  v.projects[name] = { createdAt: Date.now(), vars: {} };
                }, `created ${name}`);
                setView({ name: "projects" });
              },
              onCancel: () => setView({ name: "projects" }),
            },
            { name: "projects" },
          )
        }
        onDelete={(name) =>
          setView({
            name: "confirm",
            message: `Delete project "${name}" and all its vars?`,
            onConfirm: async () => {
              await mutate((v) => {
                delete v.projects[name];
              }, `deleted ${name}`);
              setView({ name: "projects" });
            },
            returnTo: { name: "projects" },
          })
        }
        onQuit={exit}
      />
    );
  }

  // vars view
  const projectName = view.project;
  return (
    <VarsView
      key={projectName}
      vault={vault}
      projectName={projectName}
      revealedKey={
        revealed?.project === projectName ? revealed.key : undefined
      }
      status={status}
      onSelect={async (key) => {
        setStatus(null);
        try {
          await authenticate(`abracadabra: reveal ${projectName}/${key}`);
          setRevealed({ project: projectName, key });
        } catch {
          setStatus("biometric auth failed");
        }
      }}
      onAdd={() =>
        openInput(
          {
            title: `Var name (${projectName})`,
            onSubmit: async (rawName) => {
              const key = rawName.trim();
              if (!key) return;
              openInput(
                {
                  title: `Value for ${key}`,
                  mask: true,
                  onSubmit: async (value) => {
                    if (!value) {
                      setView({ name: "vars", project: projectName });
                      return;
                    }
                    await mutate((v) => {
                      v.projects[projectName].vars[key] = {
                        value,
                        secret: true,
                        updatedAt: Date.now(),
                      };
                    }, `added ${key}`);
                    setView({ name: "vars", project: projectName });
                  },
                  onCancel: () => setView({ name: "vars", project: projectName }),
                },
                { name: "vars", project: projectName },
              );
            },
            onCancel: () => setView({ name: "vars", project: projectName }),
          },
          { name: "vars", project: projectName },
        )
      }
      onEdit={(key) => {
        const entry = vault.projects[projectName].vars[key];
        openInput(
          {
            title: `New value for ${key}`,
            initial: entry.value,
            onSubmit: async (value) => {
              if (value) {
                await mutate((v) => {
                  v.projects[projectName].vars[key] = {
                    value,
                    secret: true,
                    updatedAt: Date.now(),
                  };
                }, `updated ${key}`);
              }
              setView({ name: "vars", project: projectName });
            },
            onCancel: () => setView({ name: "vars", project: projectName }),
          },
          { name: "vars", project: projectName },
        );
      }}
      onDelete={(key) =>
        setView({
          name: "confirm",
          message: `Delete var ${key}?`,
          onConfirm: async () => {
            await mutate((v) => {
              delete v.projects[projectName].vars[key];
            }, `deleted ${key}`);
            setView({ name: "vars", project: projectName });
          },
          returnTo: { name: "vars", project: projectName },
        })
      }
      onBack={() => setView({ name: "projects" })}
      onQuit={exit}
    />
  );
}

function ProjectsView({
  vault,
  status,
  onSelect,
  onNew,
  onDelete,
  onQuit,
}: {
  vault: Vault;
  status: string | null;
  onSelect: (name: string) => void;
  onNew: () => void;
  onDelete: (name: string) => void;
  onQuit: () => void;
}) {
  const names = Object.keys(vault.projects).sort();
  const [selected, setSelected] = useState<string | null>(names[0] ?? null);

  useInput((input, key) => {
    if (input === "n") onNew();
    else if (input === "d" && selected && names.length > 0) onDelete(selected);
    else if (key.escape || input === "q") onQuit();
  });

  return (
    <Box flexDirection="column">
      <Header title="Projects" hint="↑↓ move · enter select · n new · d delete · q quit" />
      {names.length === 0 ? (
        <Text dimColor>No projects yet — press n to create one</Text>
      ) : (
        <SelectList
          items={names.map((n) => ({
            label: n,
            value: n,
            hint: `${Object.keys(vault.projects[n].vars).length} vars`,
          }))}
          onSelect={onSelect}
          onHighlight={setSelected}
        />
      )}
      <ActionsFooter status={status} />
    </Box>
  );
}

function ActionsFooter({
  status,
  extra,
}: {
  status: string | null;
  extra?: string;
}) {
  return (
    <Box marginTop={1} flexDirection="column">
      {status ? <Text color="yellow">{status}</Text> : null}
      {extra ? <Text dimColor>{extra}</Text> : null}
    </Box>
  );
}

function VarsView({
  vault,
  projectName,
  revealedKey,
  status,
  onSelect,
  onAdd,
  onEdit,
  onDelete,
  onBack,
  onQuit,
}: {
  vault: Vault;
  projectName: string;
  revealedKey?: string;
  status: string | null;
  onSelect: (key: string) => void | Promise<void>;
  onAdd: () => void;
  onEdit: (key: string) => void;
  onDelete: (key: string) => void;
  onBack: () => void;
  onQuit: () => void;
}) {
  const project = vault.projects[projectName];
  const keys = Object.keys(project.vars).sort();
  const [selected, setSelected] = useState<string | null>(keys[0] ?? null);

  useInput((input, key) => {
    if (key.upArrow && keys.length > 0) {
      const i = Math.max(0, keys.indexOf(selected ?? "") - 1);
      setSelected(keys[i]);
    } else if (key.downArrow && keys.length > 0) {
      const i = Math.min(keys.length - 1, keys.indexOf(selected ?? "") + 1);
      setSelected(keys[i]);
    } else if (input === "a") onAdd();
    else if (input === "e" && selected) onEdit(selected);
    else if (input === "x" && selected) onDelete(selected);
    else if (input === "r" && selected) void onSelect(selected);
    else if (input === "b") onBack();
    else if (input === "q") onQuit();
  });

  function mask(value: string): string {
    if (value.length <= 4) return "••••";
    return `${value.slice(0, 2)}${"•".repeat(8)}${value.slice(-2)}`;
  }

  return (
    <Box flexDirection="column">
      <Header
        title={`Project: ${projectName}`}
        hint="↑↓ move · enter reveal · a add · e edit · x delete · b back · q quit"
      />
      {keys.length === 0 ? (
        <Text dimColor>No vars yet — press a to add one</Text>
      ) : (
        keys.map((key) => {
          const isSelected = key === selected;
          const isRevealed = key === revealedKey;
          const entry = project.vars[key];
          return (
            <Box key={key}>
              <Text color={isSelected ? "magenta" : undefined}>
                {isSelected ? "❯ " : "  "}
                {key.padEnd(24)}
              </Text>
              <Text dimColor={!isRevealed}>
                {" "}
                {isRevealed ? entry.value : mask(entry.value)}
              </Text>
            </Box>
          );
        })
      )}
      <ActionsFooter status={status} extra="enter reveals value after Touch ID" />
    </Box>
  );
}
