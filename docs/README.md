# porte — Documentation

| Page | What's in it |
|---|---|
| [Configuration](configuration.md) | Every environment variable and `Config` field, and their traps |
| [Development](development.md) | Local setup, the quality gate, versioning |
| [API](api.md) | Every exported symbol — the frozen contract, package by package |

`porte` is a library. It ships no service and has no deployment of its own — it is deployed by
whatever app imports it, which is why there is no `deployment.md` here.

There is no `architecture.md` yet, deliberately. The engine, the stores and the flow are
implemented and tested end to end against a conformant in-process issuer, but no application has
adopted `porte` in production — so an architecture page would describe a request flow nobody has
walked outside a test, which is the kind of page that goes stale before it is read. It arrives
with the first adoption. Until then [SPEC.md](../SPEC.md) is the design document: it carries the
decisions, the evidence they were taken on, and the reasoning behind both.

Release history lives in [CHANGELOG.md](../CHANGELOG.md), at the repo root.

Back to the [README](../README.md).
