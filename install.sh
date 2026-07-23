#!/usr/bin/env bash
# meshmcp installer: fetches the latest signed release for this machine,
# verifies its checksum (and its cosign signature when cosign is installed),
# and installs the single static binary.
#
#   curl -fsSL https://raw.githubusercontent.com/xrey167/meshmcp/main/install.sh | bash
#
# Environment:
#   MESHMCP_VERSION   install a specific tag (default: latest release)
#   MESHMCP_BIN_DIR   install directory (default: /usr/local/bin if writable,
#                     else ~/.local/bin)
set -euo pipefail

REPO="xrey167/meshmcp"
API="https://api.github.com/repos/${REPO}"

say()  { printf '%s\n' "$*" >&2; }
fail() { say "✗ $*"; exit 1; }

# --- resolve target platform -------------------------------------------------
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux|darwin) ;;
  mingw*|msys*|cygwin*) fail "on Windows, download the .zip from https://github.com/${REPO}/releases and add meshmcp.exe to your PATH" ;;
  *) fail "unsupported OS: $os" ;;
esac
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) fail "unsupported architecture: $arch (releases cover amd64 and arm64)" ;;
esac

# --- resolve version ---------------------------------------------------------
version="${MESHMCP_VERSION:-}"
if [ -z "$version" ]; then
  version="$(curl -fsSL "${API}/releases/latest" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4 || true)"
fi
if [ -z "$version" ]; then
  say "✗ no published release found for ${REPO}."
  say "  The project may not have cut its first tag yet. Until it does, build from source:"
  say "      git clone https://github.com/${REPO} && cd meshmcp && go build -o meshmcp ./cmd/meshmcp"
  exit 1
fi

base="meshmcp_${version}_${os}_${arch}"
dl="https://github.com/${REPO}/releases/download/${version}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "→ meshmcp ${version} (${os}/${arch})"

# --- download + verify -------------------------------------------------------
curl -fsSL -o "${tmp}/${base}.tar.gz" "${dl}/${base}.tar.gz" \
  || fail "download failed: ${dl}/${base}.tar.gz"
curl -fsSL -o "${tmp}/SHA256SUMS" "${dl}/SHA256SUMS" \
  || fail "download failed: ${dl}/SHA256SUMS (refusing to install unverified binaries)"

# Checksum verification is mandatory — an installer that skips it is malware
# with extra steps.
(cd "$tmp" && grep " ${base}.tar.gz\$" SHA256SUMS | sha256sum -c - >/dev/null) \
  || fail "checksum verification FAILED for ${base}.tar.gz — do not install this file"
say "✓ checksum verified"

# Signature verification is best-effort: it runs whenever cosign is available
# (the release signs SHA256SUMS keyless via Fulcio/Rekor).
if command -v cosign >/dev/null 2>&1; then
  if curl -fsSL -o "${tmp}/SHA256SUMS.sig" "${dl}/SHA256SUMS.sig" 2>/dev/null \
     && curl -fsSL -o "${tmp}/SHA256SUMS.pem" "${dl}/SHA256SUMS.pem" 2>/dev/null; then
    cosign verify-blob \
      --certificate "${tmp}/SHA256SUMS.pem" --signature "${tmp}/SHA256SUMS.sig" \
      --certificate-identity-regexp "github.com/${REPO}" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "${tmp}/SHA256SUMS" >/dev/null 2>&1 \
      && say "✓ cosign signature verified" \
      || fail "cosign signature verification FAILED — do not install this file"
  else
    say "– signature files not found on the release; continuing on checksum alone"
  fi
else
  say "– cosign not installed; skipping signature verification (checksum verified above)"
fi

# --- install -----------------------------------------------------------------
tar -xzf "${tmp}/${base}.tar.gz" -C "$tmp" meshmcp

bindir="${MESHMCP_BIN_DIR:-}"
if [ -z "$bindir" ]; then
  if [ -w /usr/local/bin ]; then bindir="/usr/local/bin"; else bindir="${HOME}/.local/bin"; fi
fi
mkdir -p "$bindir"
install -m 0755 "${tmp}/meshmcp" "${bindir}/meshmcp"
say "✓ installed ${bindir}/meshmcp"
case ":$PATH:" in
  *":${bindir}:"*) ;;
  *) say "! ${bindir} is not on your PATH — add it, e.g.:  export PATH=\"${bindir}:\$PATH\"" ;;
esac

say ""
say "Next:  export NB_SETUP_KEY=<key from app.netbird.io>"
say "       meshmcp air up"
say "Guide: https://github.com/${REPO}/blob/main/docs/GUIDE.md"
