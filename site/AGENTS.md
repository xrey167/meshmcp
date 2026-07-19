<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# site

## Purpose
Source of the published showcase page for meshmcp. This is the human-facing marketing/overview site; the built copy is what serves at the project's GitHub Pages URL.

## Key Files
| File | Description |
|------|-------------|
| `index.html` | Self-contained showcase page (the meshmcp fabric overview, scenario cards, diagrams). |
| `knowledge-canvas.html` | Interactive provenance knowledge-graph canvas (drag-to-AirDrop demo). |
| `air.html` | Self-contained **Air** concept mockup (phone UI: Nearby / Drop / Push / Steer / Approve / Ledger). Static sample data. |
| `air-live.html` | The **functional** Air page served by `meshmcp air serve` — fetches `/api/peers` + `/api/sessions`, POSTs `/api/steer`. |

## For AI Agents

### Working In This Directory
- GitHub Pages actually deploys from the separate **`gh-pages`** branch (a legacy/classic branch build, because the account's GitHub Actions are billing-locked). Editing `site/index.html` on `main` does **not** change what's published until it's promoted to `gh-pages`.
- Keep the page self-contained (inline CSS/JS) — the Pages build has no asset pipeline.

## Dependencies

### External
- None (static HTML).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
