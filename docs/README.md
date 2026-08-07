# porte — Documentation

| Page | What's in it |
|---|---|
| [Configuration](configuration.md) | Every environment variable and `Config` field, and their traps |
| [Development](development.md) | Local setup, the quality gate, versioning |
| [API](api.md) | Every exported symbol — the frozen contract, package by package |

`porte` is a library. It ships no service and has no deployment of its own — it is deployed by
whatever app imports it, which is why there is no `deployment.md` here.

There is no `architecture.md` yet, deliberately. The contract is frozen but nothing implements
it, so an architecture page could only describe a request flow that does not exist. It arrives
with the v0.1 implementation, and until then [SPEC.md](../SPEC.md) is the design document — it
carries the decisions, the evidence they were taken on, and the reasoning behind both.

Release history lives in [CHANGELOG.md](../CHANGELOG.md), at the repo root.

Back to the [README](../README.md).
