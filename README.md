# porte

The authentication kit for the [Facile Suite](https://facile.studio). The OIDC plumbing every
Facile API needs and none of them should be re-writing.

**Unreleased and unproven.** The engine and the stores are written and tested; nothing has run
against a real Authentik yet, and no app has adopted it. Read [SPEC.md](SPEC.md) before writing
any code — it carries the decisions, the contract, and the reasoning behind both.

## What it does

- Mounts `/auth/oidc` and its callback against any OIDC provider, Authentik today, with PKCE, a
  nonce and a constant-time state comparison — all three missing from the six apps it replaces
- Verifies the ID token, upserts the user through an interface the app implements, issues a
  session
- Serves `/auth/config` so a frontend knows whether SSO is available and whether it is mandatory
- Carries the suite's `SSO_ONLY` and `OIDC_*` environment conventions
- Keeps the role model pluggable, so `IsAdmin`, workspace roles and enum roles all still work
- Stores sessions as hashed opaque tokens — `HttpOnly`, `__Host-` prefixed cookie in browsers,
  `Bearer` for CLIs and API tokens — with a `database/sql` implementation in `pg/`
- Retires a browser session nobody has used for a week, inside the thirty-day absolute lifetime,
  and leaves CLI and API tokens alone because a nightly job is idle by design
- Gives every CLI the same login: browser opens, user signs in, a one-time code comes back
- Fetches IdP avatars behind an SSRF guard that checks the address at connect time, closing the
  DNS-rebinding window every existing copy leaves open, and unwraps the IPv6 forms that smuggle
  an IPv4 metadata address past `net.IP`'s own predicates

## Wiring it

```go
store := pg.New(db)
kit, err := oidc.New(ctx, cfg, oidc.Deps{
	Users:      store.Users(),
	Identities: store.Identities(),
	Sessions:   store.Sessions(),
	Codes:      store.LoginCodes(),
})
kit.Mount(router)

router.Group(func(r chi.Router) {
	r.Use(kit.RequireAuth)
	r.Get("/things", handler) // porte.From(ctx) inside
})
```

## Why

Six Go apps — Nuage, Courrier, Plume, Agenda, Vision, Sablier — ship roughly 900 lines of
near-identical OIDC client code each, and it has drifted. `porte` is the single version.

It also fixes three things while extracting: the flow gains PKCE, a nonce, and a constant-time
state comparison. Written once here instead of six times in the apps.

## Stack

| Layer | Tech |
|---|---|
| Runtime | Go 1.25, [go-oidc](https://github.com/coreos/go-oidc), `golang.org/x/oauth2`, [tronc](https://github.com/FacileStudio/tronc) |
| Storage | Sessions through an interface; `pg/` needs only a `*sql.DB` |

## Status

| Version | Scope |
|---|---|
| v0.1 | OIDC only. Written; proven on the e-commerce demo and Nuage before tagging |
| v0.2 | Local email/password, argon2 |
| v0.3 | `porte/espace` — spaces, membership, `RequireRole` |

## Documentation

| Doc | What's in it |
|---|---|
| [Specification](SPEC.md) | What to build, what was decided and why, the evidence behind both |
| [Configuration](docs/configuration.md) | Every environment variable and `Config` field, and their traps |
| [Development](docs/development.md) | Local setup, the quality gate, versioning |
| [API](docs/api.md) | Every exported symbol — the frozen contract, package by package |

There is no `docs/architecture.md` yet. It arrives once the flow has run against a real
provider: a page describing a request path nobody has walked is a page that documents an
intention.

---

Part of the [Facile Suite](https://facile.studio) — self-hosted tools for creative studios
and freelancers. One login, zero cloud dependency.
