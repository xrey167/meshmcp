# Governed Plugin Marketplace (F14)

meshmcp extends by **compile-time Go interfaces** — it never loads code at
runtime (see [EXTENSIONS.md](EXTENSIONS.md)). The marketplace does not change
that: it is a governed exchange for **signed bundle manifests**, not a code
loader. A manifest is an Ed25519-signed, tamper-evident description of a plugin
bundle (a policy pack, a tool backend, a decision hook, an audit sink) bound to
the bundle's content hash. Publishing mints one; discovery lists them;
**install** verifies a manifest against a *pinned* authority key **and** the
bundle bytes, then records a **metered, audited grant**. The plugin code itself
is still compiled in and listed by `meshmcp plugins`.

> Every install is a mintable grant and every use is attributable — no public
> registry, no unsigned code, nothing loaded at runtime.

The trust model is identical to signed capabilities ([capability.go](../policy/capability.go)):
a manifest is admissible only if signed by an authority key the consumer has
**pinned**. An unpinned signer is refused even when its own signature is valid.

## Trust boundary — decided: manifests govern distribution, never execution

Manifests are deliberately **not** a runtime execution gate, and this is a
decision, not an omission. Execution is gated once, at **compile time**: a
plugin runs because it was compiled into the binary you built (the
no-dynamic-loading stance in [EXTENSIONS.md](EXTENSIONS.md)), and
`meshmcp plugins` lists exactly that set. A startup manifest check over
compiled-in code would verify a claim about bytes that are already part of the
binary's own provenance — the binary's signature/attestation
(`docs/RELEASE-CHECKLIST.md`, cosign) is the correct place to prove those, and
a runtime check could add only a false sense of a second gate. What a manifest
proves is **distribution and attribution**: who published a bundle, what its
content hash was, who installed it, under which metered, audited grant.
Operators who want execution-side provenance should verify the *binary*
(cosign) rather than expect the marketplace layer to re-check itself.

## Manifest kinds
`policy-pack` · `tool-backend` · `decision-hook` · `audit-sink`. A manifest of
any other kind is refused at issue time.

## Commands
| Command | Purpose |
|---|---|
| `market keygen [--out f]` | Mint the Ed25519 authority key publishers sign with and consumers pin (`0600`). |
| `market publish --key <f> --name <n> --kind <k> --bundle <path> [--bundle-version --summary --cost --ttl --dir]` | Hash the bundle, sign a manifest, print the token (and write it to a catalog `--dir`). |
| `market list --dir <d>` | List a catalog (advertising, not authorizing — signatures are not checked at list time). |
| `market verify --pubkey <hex> --manifest <f> [--bundle <path>]` | Verify a manifest against pinned keys; with `--bundle`, also check the content hash. |
| `market install --pubkey <hex> --manifest <f> --bundle <path> --audit <f> [--as <id> --peer-key <k>]` | Verify manifest + bundle, then append a metered, audited install grant. |

## End-to-end
```sh
# publisher
meshmcp market keygen --out key.json                 # → public key <PUB>
meshmcp market publish --key key.json --name least-privilege \
  --kind policy-pack --bundle least-privilege.yaml --bundle-version 1.0.0 \
  --cost 4 --dir catalog                             # signs + publishes

# consumer (pins <PUB>)
meshmcp market list --dir catalog
meshmcp market verify  --pubkey <PUB> --manifest catalog/least-privilege.manifest --bundle least-privilege.yaml
meshmcp market install --pubkey <PUB> --manifest catalog/least-privilege.manifest \
  --bundle least-privilege.yaml --audit market.jsonl --as alice.mesh
```
A tampered bundle fails `verify`/`install` on the content-hash check; an install
signed by an unpinned key is refused. Each install is one audited record
(`method: market/install`, `cost:` set), so it rolls up in `meshmcp budget` and
is covered by the tamper-evident chain (`meshmcp audit verify`).

## Distribution over the mesh
The catalog is a plain directory of manifest files, so it rides the existing
zero-exposure transport: `meshmcp drop` a catalog to a peer, or serve it from a
backend registered in the [registry](../registry/) — no public registry and no
open port. Verification and metering happen on the consumer side against the
pinned authority key.
