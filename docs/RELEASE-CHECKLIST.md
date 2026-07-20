# Release Checklist

meshmcp is pre-1.0. Releases are cut by pushing a semver tag (`vX.Y.Z`), which
triggers `.github/workflows/release.yml`.

## Before tagging

- [ ] `gofmt -l .` is clean; `go vet ./...`, `go build ./...`, `go test ./...`,
      and `go test -race ./...` pass on the default branch.
- [ ] `govulncheck ./...` reviewed; any findings triaged or documented.
- [ ] `CHANGELOG.md` updated: move the relevant `[Unreleased]` items under the
      new version heading with the date.
- [ ] `docs/CAPABILITY-MATRIX.md` reflects what actually shipped (stable / beta /
      experimental / planned).
- [ ] No headline claim exceeds what code + tests establish (spot-check the
      README against `docs/THREAT-MODEL.md`).
- [ ] License status is consistent (`LICENSE`, `LICENSE-DECISION.md`, README).

## Tag and publish

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

The release workflow then:

1. Builds cross-platform archives (`linux/amd64`, `linux/arm64`, `darwin/amd64`,
   `darwin/arm64`, `windows/amd64`) with a version-stamped binary.
2. Writes `SHA256SUMS`.
3. Generates an SPDX SBOM.
4. Signs `SHA256SUMS` with **cosign keyless** (Sigstore Fulcio/Rekor), emitting
   `SHA256SUMS.sig` + `SHA256SUMS.pem`.
5. Creates the GitHub release with all artifacts.

## After publishing — verify

- [ ] Download the checksums, signature, and certificate and verify:

  ```bash
  cosign verify-blob \
    --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
    --certificate-identity-regexp 'https://github.com/xrey167/meshmcp/.*' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    SHA256SUMS
  ```

- [ ] `sha256sum -c SHA256SUMS` against the downloaded archives.
- [ ] SBOM is attached and parses.

## Notes / known caveats

- **Cross-compilation:** the target matrix builds with `CGO_ENABLED=0`. Some
  netbird/wireguard code paths may need per-target adjustment; if a target fails
  to build, drop it from the matrix or provide a CGO cross-toolchain for that
  target, and note it in the release.
- **Container image / Homebrew / Scoop:** not yet automated — add when the
  distribution story is finalized.
- **Provenance/attestation (SLSA):** cosign keyless signing of the checksums is
  the current provenance floor; a full SLSA provenance attestation is a
  follow-up.
