# Workspace modules

The go.work workspace composes several modules. This records what each is and
the decisions taken for the two named-but-empty placeholders (backlog task 20).

## Modules

| Module | Git remote | Role |
|--------|-----------|------|
| `meshmcp` | `github.com/xrey167/meshmcp` | The gateway / control-plane / Air binary and its libraries — this repo. |
| `meshmcp-server` | *(separate)* | The capability plane: `promptd`, `agentd`, `skilld`, `evald` — zero-exposure identity-scoped stdio MCP backends behind the gateway, plus the shared `manifest`/`modcheck`/`render`/`scope`/`store` libraries. |
| `meshmcp-client` | *(separate)* | The thin typed CLI (`meshcap`) and client SDKs. |
| `meshmcp-service` | *(separate, empty)* | Reserved for the cross-store doctor — see below. |
| `meshmcp-app` | *(separate, empty)* | Reserved placeholder — see below. |

## `meshmcp-service` — the cross-store doctor

`meshmcp-server`'s design (promptd/agentd/skilld plan §2.2 / M7) calls for a
cross-store doctor that detects dangling references between the capability
stores before they bite at serve time — e.g. an agent definition referencing a
prompt or skill version that no longer exists in its store. The doctor reads
the shared content-addressed artifact store (`meshmcp-server/store`) and the
per-backend registries, and reports unresolved references.

**Status: scoped, deferred to its own module.** The doctor belongs in
`meshmcp-service`, which imports `meshmcp-server/store`. In this workspace those
modules are checked out **without a configured git remote**, so the doctor's
code cannot be shipped as a `meshmcp` pull request — it is not part of this
repository. It is tracked here as a follow-up gated on a publishing home for the
`meshmcp-service` module (the same class of external blocker as the native
mobile shell: the work is understood, the infrastructure to ship it is not
present in this repo). When `meshmcp-service` gains a remote, the doctor lands
there against the `meshmcp-server/store` change-journal API.

## `meshmcp-app` — decision: no reserved purpose

`meshmcp-app` was an unfilled placeholder directory with no committed code and
no design that distinguishes it from the shipped surfaces (`air serve` already
provides the phone-first web app; `meshmcp mcp` provides the assistant app;
native shells are covered by the `mobile/` gomobile bindings and tracked
separately). It carries **no reserved purpose** and should be removed rather
than left implying planned work. It is not referenced by `go.work` and nothing
imports it; deleting the empty directory is a no-op for every build. (The
directory is not tracked in this repository, so its removal is a local/workspace
cleanup, not a `meshmcp` code change.)
