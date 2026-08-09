# porte — Documentation

| Page | What's in it |
|---|---|
| [Configuration](configuration.md) | Every environment variable and `Config` field, and their traps |
| [Development](development.md) | Local setup, the quality gate, versioning |
| [API](api.md) | Every exported symbol — the frozen contract, package by package |

`porte` is a library. It ships no service and has no deployment of its own — it is deployed by
whatever app imports it, which is why there is no `deployment.md` here.

There is no `architecture.md` yet, deliberately, though the reason moved on in v0.2. It used to
be that no application had adopted `porte`, so the page would have described a request flow
nobody had walked outside a test. Journal has since adopted it in production and walks both the
federated and the password path. What the page waits on now is a **second** adopter: drawn from
one app it would document that app's wiring rather than `porte`'s shape, and the one thing v0.2
proved is that a single consumer is enough to move a package boundary. Until then
[SPEC.md](../SPEC.md) is the design document: it carries the decisions, the evidence they were
taken on, and the reasoning behind both.

Release history lives in [CHANGELOG.md](../CHANGELOG.md), at the repo root.

Back to the [README](../README.md).
