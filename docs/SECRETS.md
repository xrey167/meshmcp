# secrets — the credential broker

Agents need credentials — an API key for Stripe, a token for an internal
service — to do useful work. The dangerous status quo is to hand the agent the
raw secret: now it lives in the model's context, its logs, its prompt history,
and anything the agent can be talked into exfiltrating.

meshmcp removes the secret from the agent entirely. Because the gateway already
sits in the data path and parses every `tools/call`, it can **inject
credentials by cryptographic identity**: the agent references a secret by name,
and the real value is spliced in on the way to the backend — the agent only ever
holds a reference.

```
agent ──▶  tools/call charge { "auth": "Bearer {{secret:stripe_key}}" }
                    │
              meshmcp gateway   ── authorize by WireGuard identity + grant
                    │           ── refuse if the session is tainted
                    │           ── audit the USE (name, never value)
                    ▼
backend ◀──  tools/call charge { "auth": "Bearer sk_live_…" }   ← value only here
```

The agent never sees `sk_live_…`. Neither does the trace, nor the audit log.

## How it works

- **Reference syntax.** Inside any string argument of a `tools/call`, the agent
  writes `{{secret:NAME}}`. The broker substitutes the resolved value,
  JSON-escaped, so a value containing quotes or newlines cannot break the
  message or escape its string context.
- **Identity-gated.** A `grant` decides which peers may inject which secrets
  into which tools. Peers are matched by `pubkey:<key>` or FQDN glob — the same
  cryptographic identity everything else keys off. An ungranted reference denies
  the whole call inline; the backend never sees it.
- **Injected last.** Substitution happens *after* the call is authorized,
  audited, and traced, so the resolved value reaches only the backend. The trace
  records the reference form (`{{secret:stripe_key}}`); the audit records the
  secret **name and caller, never the value**.
- **Composes with the firewall.** A grant's `block_labels` refuses injection
  when the session carries a data-flow label. With `block_labels: ["tainted"]`,
  a session that has touched untrusted content (a `taint_source` tool) can no
  longer obtain a credential — so injected instructions can't cause a secret to
  be used. Credential-exfiltration defense at the network layer.

## Configure

Secrets require a stdio backend with a policy (injection happens at the
enforcement point). Store values out of band — a mode-0600 JSON file and/or the
environment — never in the config:

```yaml
backends:
  - name: payments
    stdio: ["./mcpserver"]
    policy: { default_allow: false, rules: [ { peers: ["*"], tools: ["charge"], allow: true } ] }
    secrets:
      file: ./secrets.json          # {"stripe_key":"sk_live_...","openai":"sk-..."}
      env_prefix: MESHMCP_SECRET_    # fallback: $MESHMCP_SECRET_stripe_key
      grants:
        - peers: ["pubkey:<billing-agent-key>"]
          secrets: ["stripe_key"]
          tools: ["charge", "refund"]
          block_labels: ["tainted"]   # no credentials for a tainted session
```

A file store is layered under environment variables (`Chain`): the file for
local development, the environment for production. Validate a config without
ever revealing a value:

```bash
meshmcp secrets check --config examples/secrets.yaml
# backend "payments": 2 grant(s)
#   file ./secrets.json: 2 secret name(s) available: [openai stripe_key]
#   env: secrets read from MESHMCP_SECRET_* (values never listed)
```

## Stores

| Store | Source | Use |
|---|---|---|
| `FileStore` | JSON `{"name":"value"}` file (0600) | local dev, small deployments |
| `EnvStore` | `$PREFIX+NAME` environment variables | production (systemd creds, k8s secrets) |
| `Chain` | first hit across stores | file under env |

The `Store` interface is one method (`Get(name) (value, ok)`), so a KMS / Vault
backend is a small addition — the broker, grants, audit, and taint-gating stay
the same.

## Threat model & boundaries

- **What it protects:** the agent (and its context, logs, prompt history) never
  holds the raw credential; every use is identity-attributed and recorded in the
  tamper-evident audit; a tainted session cannot obtain a secret.
- **What it does not:** the *backend* receives the resolved value to authenticate
  upstream — if a backend tool is malicious or logs its own arguments, it sees
  the secret. Scope grants tightly (per tool), and treat backends as trusted.
- **v1 scope:** injection is into stdio `tools/call` arguments (where the gateway
  parses JSON-RPC). HTTP-backend header injection is a natural follow-on on the
  forward/HTTP path.
- **Confused-deputy — cover it with taint:** a `{{secret:NAME}}` reference is
  resolved wherever it appears in an outbound call, including argument fields
  that may derive from untrusted, model-supplied, or retrieved content. The
  guard against a jailbroken agent tricking the gateway into injecting a secret
  is the label lattice: any tool that can *carry untrusted content into a
  credentialed call* must taint the session (`taint_source: true` on the tool
  that pulls the content) so the grant's `block_labels: ["tainted"]` refuses the
  injection. Rule of thumb: **every secret grant should set
  `block_labels: ["tainted"]`, and every untrusted-content source should set
  `taint_source: true`** — the broker already refuses injection into a tainted
  session; this is how you make sure the session is tainted when it should be.
- **Permissions:** a file store MUST be mode `0600` — `NewFileStore` refuses a
  group- or world-accessible secrets file rather than read it.

## Reference implementation

`meshmcp/secrets` (`store.go`, `broker.go`) implementing `policy.SecretResolver`,
attached to the enforcement `Filter` via `SetSecretResolver`. Command:
`meshmcp secrets check`.
