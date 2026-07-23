---
name: Bug report
about: Something misbehaves — a command errors, a policy decision is wrong, a session drops
labels: bug
---

## What happened

<!-- One or two sentences. Paste the exact error line if there is one. -->

## What you expected

## How to reproduce

```console
$ meshmcp …
```

## Diagnostics

Run `meshmcp diag --bundle diag.tar.gz` and attach the bundle — it contains
your config with secrets redacted, the doctor report, the audit chain verdict,
and version info. If you'd rather not attach it, paste the output of
`meshmcp diag` (same content, printed) after reviewing it.

- meshmcp version (`meshmcp version`):
- OS / arch:
- Running under systemd / Docker / directly:

> **Security issues:** do NOT open a public issue — see [SECURITY.md](../../SECURITY.md).
