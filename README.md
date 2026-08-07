# porte

The authentication kit for the [Facile Suite](https://facile.studio). The OIDC plumbing every
Facile API needs and none of them should be re-writing.

**Nothing is implemented yet.** What exists is the specification and the contract it freezes:
`porte.go`, `identity.go` and `session.go` hold the types, interfaces and wire shapes, with no
behaviour behind them and no dependency outside the standard library. Read [SPEC.md](SPEC.md)
before writing any code — it carries the decisions, the contract, and the reasoning behind both.

## What it will do

- Mount `/auth/oidc` and its callback against any OIDC provider, Authentik today
- Verify the ID token, upsert the user through an interface the app implements, issue a session
- Serve `/auth/config` so a frontend knows whether SSO is available and whether it is mandatory
- Carry the suite's `SSO_ONLY` and `OIDC_*` environment conventions
- Keep the role model pluggable, so `IsAdmin`, workspace roles and enum roles all still work
- Store sessions as hashed opaque tokens — `HttpOnly` cookie in browsers, `Bearer` for CLIs and
  API tokens — with a `database/sql` implementation in `pg/`
- Give every CLI the same login: browser opens, user signs in, a one-time code comes back

## Why

Six Go apps — Nuage, Courrier, Plume, Agenda, Vision, Sablier — ship roughly 900 lines of
near-identical OIDC client code each, and it has drifted. `porte` is the single version.

It also fixes three things while extracting: the flow gains PKCE, a nonce, and a constant-time
state comparison. Written once here instead of six times in the apps.

## Stack

| Layer | Tech |
|---|---|
| Runtime | Go 1.24, [go-oidc](https://github.com/coreos/go-oidc), `golang.org/x/oauth2`, [tronc](https://github.com/FacileStudio/tronc) |
| Storage | Sessions through an interface; `pg/` needs only a `*sql.DB` |

## Status

| Version | Scope |
|---|---|
| v0.1 | OIDC only. Proven on the e-commerce demo and Nuage before tagging |
| v0.2 | Local email/password, argon2 |
| v0.3 | `porte/espace` — spaces, membership, `RequireRole` |

## Documentation

| Doc | What's in it |
|---|---|
| [Specification](SPEC.md) | What to build, what was decided and why, the evidence behind both |
| [Configuration](docs/configuration.md) | Every environment variable and `Config` field, and their traps |
| [Development](docs/development.md) | Local setup, the quality gate, versioning |
| [API](docs/api.md) | Every exported symbol — the frozen contract, package by package |

There is no `docs/architecture.md` yet: the contract is frozen but nothing implements it, so the
page could only describe a request flow that does not exist. It arrives with v0.1.

---

Part of the [Facile Suite](https://facile.studio) — self-hosted tools for creative studios
and freelancers. One login, zero cloud dependency.
