# porte

The authentication kit for the [Facile Suite](https://facile.studio). The OIDC plumbing every
Facile API needs and none of them should be re-writing.

**Nothing is built yet.** This repo currently holds the specification only. Read
[SPEC.md](SPEC.md) before writing any code — it carries the decisions, the frozen contract, and
the reasoning behind both.

## What it will do

- Mount `/auth/oidc` and its callback against any OIDC provider, Authentik today
- Verify the ID token, upsert the user through an interface the app implements, issue a session
- Serve `/auth/config` so a frontend knows whether SSO is available and whether it is mandatory
- Carry the suite's `SSO_ONLY` and `OIDC_*` environment conventions
- Keep the role model pluggable, so `IsAdmin`, workspace roles and enum roles all still work
- Store sessions as hashed opaque bearer tokens, with a `database/sql` implementation in `pg/`

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
| v0.1 | OIDC only. Proven on Comptoir and Nuage before tagging |
| v0.2 | Local email/password, argon2 |
| v0.3 | `porte/espace` — spaces, membership, `RequireRole` |

## Documentation

| Doc | What's in it |
|---|---|
| [Specification](SPEC.md) | What to build, what was decided and why, the contract to freeze |

`docs/` follows the suite standard once there is an implementation to document.

---

Part of the [Facile Suite](https://facile.studio) — self-hosted tools for creative studios
and freelancers. One login, zero cloud dependency.
