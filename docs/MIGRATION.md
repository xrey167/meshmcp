# Migration Notes

Breaking changes that require action when upgrading. Newest first.

## Go module path: `meshmcp` → `github.com/xrey167/meshmcp`

**What changed.** The module declared in `go.mod` was renamed from the
non-canonical `module meshmcp` to the canonical repository path
`module github.com/xrey167/meshmcp`. Every internal import was updated
accordingly (e.g. `"meshmcp/policy"` → `"github.com/xrey167/meshmcp/policy"`).

**Why.** A bare `meshmcp` module path cannot be fetched with `go get` /
`go install`, breaks module-aware tooling (proxy, `govulncheck`, SBOM
generators, `pkg.go.dev`), and prevents any external package from importing
these libraries. The canonical path is required for distribution and supply-
chain tooling.

**Who is affected.**

- **End users building from source:** no action. `go build ./...`,
  `go build -o meshmcp ./cmd/meshmcp`, and `go test ./...` work unchanged inside the repo.
- **Anyone importing these packages** (e.g. `meshmcp/policy`,
  `meshmcp/mcpclient`) from another module: update your imports to the
  `github.com/xrey167/meshmcp/...` prefix. Once a version is tagged you can
  `go get github.com/xrey167/meshmcp@<tag>`.
- **Open branches / PRs** based on the old path will conflict on import lines;
  rebase and re-run the same `"meshmcp/` → `"github.com/xrey167/meshmcp/`
  rewrite over `*.go`, plus the `go.mod` module line.

**Not affected.** String literals that merely contain `meshmcp` — the server
name (`ServerInfo.Name = "meshmcp"`), the CLI/binary name, mesh peer names such
as `meshmcp-agent`, and documentation — were intentionally left unchanged; only
import paths and the module directive were rewritten.

**Verification.** `go build ./...`, `go vet ./...`, and compilation of every
test binary pass after the rename.
