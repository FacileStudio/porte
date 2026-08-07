# porte — Specification

The authentication kit for the Facile Suite. This document is the brief for building it: what
it is, what was decided and why, the contract it must freeze, and what it must not become.

Written 2026-08-07, before any code. Everything below that describes existing apps was read
from source on that date, not recalled.

---

## 1. What porte is

Three layers get confused in conversation. They are different things:

| Layer | What | Who owns it |
|---|---|---|
| Protocol | OIDC — discovery, JWKS, auth code flow | Nobody here. `go-oidc` does it |
| **App plumbing** | `/auth/oidc` routes, sessions, cookie, user upsert, avatar, `SSO_ONLY`, role hook | **`porte`** |
| Identity provider | The server that issues identities | **Authentik**, at `sso.facile.studio` |

`porte` is the middle layer only. It is not an OIDC implementation — OIDC is a standard, and
Authentik and Dex both ship no client SDK at all for exactly that reason. What `porte` holds is
the *Facile-specific* glue that six Go apps have each written separately.

`porte` names the door **in your app**, matching how `tronc`, `caisse` and `enveloppe` are
named: each names the component the library contributes inside the app, never an external
service.

### What it is not

- **Not the IdP.** Authentik keeps its own name. We do not alias a third-party product.
- **Not a future IdP's client SDK.** If Facile ever builds its own identity provider, that
  server gets a fresh name chosen then, and `porte` keeps working against it unchanged —
  because `porte` only speaks standard OIDC. That is the whole point of freezing the contract.
- **Not MFA.** TOTP, WebAuthn and passkeys belong in the IdP, never in this library. That is
  the reason a central IdP exists: the day it has TOTP, all seven apps have it with zero lines
  changed. If MFA touched this library, adding a factor would mean redeploying seven apps.

---

## 2. Why it exists — the evidence

Read from source, 2026-08-07.

Six Go apps ship near-identical OIDC client code: **Nuage, Courrier, Plume, Agenda, Vision,
Sablier**. Each has 6 files under `apps/api/modules/auth/` plus `internal/authcrypto/`, roughly
900 lines. Journal has `authcrypto` and sessions but no OIDC at all. Capsule has no auth by
design.

`internal/oidcavatar/` — HTTPS validation, private-IP/SSRF rejection, download, store — is
copy-pasted in six apps as well.

The OIDC surface is **identical across all six**:

```
GET  /auth/config          → {"sso_only": bool, "oidc_enabled": bool}
GET  /auth/oidc            → redirect to the IdP
GET  /auth/oidc/callback   → exchange, verify, upsert, issue session
```

Everything else has drifted:

| Route | Apps that have it |
|---|---|
| `POST /auth/logout` | Nuage, Courrier, Agenda (others via a different registration shape) |
| `POST /auth/sync-profile` | Nuage, Plume, Vision |
| `POST /auth/register`, `POST /auth/login` | Nuage, Plume, Vision, Sablier — gated on `!SSO_ONLY` |
| `GET/PUT /auth/me`, `PUT /auth/password` | Plume, Vision |
| `POST /auth/oidc/exchange` | Plume only — believed to be the CLI token path |

That split is the map of what belongs in v0.1 (the identical part) and what has to be settled
before v0.2 (the drifted part).

---

## 3. Decisions already taken

Do not re-litigate these. Each has a reason recorded.

| Decision | Reason |
|---|---|
| Name is `porte`, not `sésame` | Matches the naming convention (the component *in* your app); no accent to lose in the module path; "sésame" names the act of opening, not identity |
| Authentik keeps its name | Never rename someone else's product; it removes the permanent "Porte is actually Authentik" explanation |
| `porte.facile.studio` → **`sso.facile.studio`** | Frees the name, and `sso.` survives replacing Authentik whereas `authentik.` would need a second rename |
| The old `Porte` repo → `authentik-config` | 93 lines of Authentik policy scripts. It frees the name and has no reason to grow. **Done locally 2026-08-07; the GitHub repo still needs renaming.** |
| A future in-house IdP gets a new name, chosen when built | Naming a project you have not decided to build is a free commitment. Right register when it comes: institutions that issue identity papers — `consulat`, `préfecture`, `mairie` |
| Rebuilding Authentik is **not** decided | `porte`'s value does not depend on it. "Zéro dépendance cloud" does not apply — Authentik is already self-hosted on la ruche. Reopen the question only when `porte` runs on all seven apps, the OIDC contract has been stable for months, and something concrete is blocked by Authentik |
| Forced logout of production users is acceptable | User decision, 2026-08-07. This removes the whole backward-compatible session migration problem: one canonical session model, no dual-read, no cookie compatibility shims |
| Password hashing is already settled | All seven Go apps use argon2 today. No hash migration needed. (Journal carries bcrypt *alongside* argon2 — look at it during extraction) |

---

## 4. Scope

### v0.1 — OIDC only

The identical part, extracted and hardened. No local password: apps that still need
email/password keep their own code in parallel for now, and lose roughly 60% of their auth
code rather than 100%.

### v0.2 — local password

`register`, `login`, `me`, `password`, argon2 via the extracted `authcrypto`. Blocked on
reconciling the drift in §2 and the role model in §7.

### v0.3 — `porte/espace`

A **subpackage**, same repo, same tags. `Space` / `SpaceMember` models, membership queries and
`RequireRole(spaceID, role)`. Apps without spaces (Journal, Comptoir) simply do not import it —
the pattern already used by `tronc/migrate`, `tronc/testdb` and `caisse/pg`.

Evidence: `Space`/`SpaceMember` is copy-pasted in Nuage, Sablier, Agenda, Courrier and Plume,
and as `Workspace` in Vision. Already drifted — `modules/spaces/types.go` is 54/49/40/39/45
lines with five different hashes, and the wire contracts genuinely diverge (`ID` is a string in
Courrier and an int64 in Nuage; Nuage wraps lists, Courrier returns bare arrays).

**Scope limit, deliberate:** models, membership and role resolution only. **No CRUD, no
invitation flow, no HTTP routes.** Those stay in each app, because converging them would mean
migrating six SvelteKit frontends, and because the authorization logic is the only part where
drift is a security bug rather than cosmetics. If spaces ever grow a real product surface —
email invitations, quotas, per-space billing — that is when it earns its own repo.

`FacileID` carries a unique index, which only makes sense if the same space is meant to exist
in several apps. Confirmed intent: **sync via Nook later**, so the whole park's spaces work
together. Treat `FacileID` as the sync key from the start, even though the sync comes later.
Check first: the `enveloppe` contract keys on `actor_email` and will need to carry a *space*
identity — that is a change to `enveloppe`, to make before `porte/espace`, not during.

---

## 5. The frozen contract

This is the part that costs the most if it is wrong, and the reason to read six
implementations before writing one line. Freezing it now is what makes a future
Authentik → in-house IdP swap a config change rather than a rewrite.

### Environment

| Variable | Required | Meaning |
|---|---|---|
| `OIDC_ISSUER` | no | Issuer URL. **Its presence is what enables OIDC** — this is the existing convention, keep it |
| `OIDC_CLIENT_ID` | with issuer | |
| `OIDC_CLIENT_SECRET` | with issuer | |
| `OIDC_REDIRECT_URL` | with issuer | Must match the Authentik application |
| `OIDC_SUCCESS_URL` | with issuer | Where the browser lands after a successful callback |
| `SSO_ONLY` | no | When true, local password routes are not registered at all |

Authentik application slug convention, unchanged: `sso.facile.studio/application/o/<app>/`.

### Routes

```
GET  /auth/config          {"sso_only": bool, "oidc_enabled": bool}   no auth
GET  /auth/oidc            302 to the IdP                             no auth
GET  /auth/oidc/callback   302 to OIDC_SUCCESS_URL                    no auth
POST /auth/logout          {"logged_out": true}                       session required
POST /auth/sync-profile    refresh profile from the IdP               session required
```

### Sessions

Opaque bearer token, generated randomly, **stored hashed** (the existing `authcrypto.NewToken`
/ `HashToken` pair), presented as `Authorization: Bearer …`. Keep this — it is stateful by
design, revocable, and already what all six do.

`porte` owns the sessions table and ships `porte/pg` for it, following `caisse/pg`: an
interface plus a `database/sql` implementation, so no ORM is forced on consumers.

### The app owns its users

`porte` must never own the users table. Apps have genuinely different user columns. `porte`
gets an interface and calls it after verifying the ID token:

```go
type UserStore interface {
	UpsertFromOIDC(ctx context.Context, claims Claims) (userID int64, err error)
}
```

Fields the current implementations write on upsert, as a checklist for `Claims`: email,
email_verified, name, picture URL, plus the app's own `avatar_url` / `avatar_source` /
`oidc_picture_url` / `oidc_access_token` / `oidc_refresh_token` / `oidc_token_expiry` /
`profile_synced_at`. `profile_synced_at` exists to rate-limit profile refreshes — keep it.

### Roles are a hook, not an enum

`porte` must not arbitrate the role model. Today: Nuage uses `IsAdmin bool` with first-user-
admin, Vision uses workspace-scoped roles, the TS family uses a `USER`/`ADMIN` enum. All three
have to keep working.

---

## 6. Security — fix these while extracting

Read from `Nuage/apps/api/modules/auth/oidc.go` on 2026-08-07. The existing flow is decent and
should be preserved, with three additions. Writing them once here instead of six times is a
concrete argument for the library.

**Already good, keep it:** `state` is random per request, stored in a cookie that is `HttpOnly`,
`Secure` when the success URL is https, `SameSite=Lax`, TTL-bounded, compared on callback and
cleared immediately after. The ID token is verified through `go-oidc`'s verifier.

**Missing — add:**

1. **PKCE (S256).** `AuthCodeURL(state)` is called with no code challenge. Add
   `oauth2.S256ChallengeOption`, with the verifier carried in a cookie alongside the state.
2. **Nonce.** No nonce is generated or checked against the ID token claim. Generate one per
   request, carry it with the state, and verify it after `Verify` returns.
3. **Constant-time state comparison.** The check is a plain `!=`. Use
   `subtle.ConstantTimeCompare`. Free, and removes the question entirely.

**Non-negotiable:** do not hand-roll protocol or crypto. `go-oidc` for verification,
`golang.org/x/oauth2` for the flow, `argon2` for hashing. This is the one place custom code is
unacceptable.

---

## 7. Open questions — settle before coding the affected part

1. **CLI token flow.** Plume has a `POST /auth/oidc/exchange` the others lack, believed to be
   how `plume`'s CLI authenticates. The suite has six CLIs. Does `porte` v0.1 own a device/token
   flow, or is it deferred? Read Plume's implementation first.
2. **`/auth/me` and `/auth/password`** — v0.2 of `porte`, or permanently app-side? They touch
   the app's user columns, which argues app-side.
3. **Journal's bcrypt**, sitting next to argon2. Legacy path or a dependency? Look before
   assuming.
4. **Role hook shape** — an interface the app implements, or claims carried opaquely on the
   session and interpreted by the app? The second is smaller; the first gives `porte` a usable
   `Require` middleware.

---

## 8. Package layout

```
porte/          the OIDC contract, sessions, middleware. go-oidc + oauth2 + tronc
porte/pg        Postgres session store. database/sql only, no ORM
porte/espace     v0.3. Space/SpaceMember, membership, RequireRole
```

Dependency rules, following `caisse`:

- `tronc/errors` for the suite error envelope, so `httpjson.WriteError` maps failures to the
  right status with no glue in the app. This couples `porte` to the suite deliberately.
- **No GORM.** All six apps use it, but forcing it is a heavier commitment than anything the
  suite shares today, and it is what pushed `tronc` to split `migrate` and `testdb` into
  separate modules. `database/sql` keeps everything in one module.
- Go floor 1.24, matching `tronc` and `caisse`.

---

## 9. Validation and rollout

**Before tagging v0.1.0:** prove it on **Comptoir** (greenfield, no live sessions to break) and
**Nuage** (the extraction source, so the most honest feedback on whether the abstraction fits).
This is the sequence that made `tronc` right — written, proven on one, rolled out after.

**Then** the remaining five, in one pass each. Change `OIDC_ISSUER` to `sso.facile.studio` in
the same commit that adopts the library: the app's env is already being edited, so it costs one
extra line. Done separately it is a second tour of ten repos.

Ten backends carry OIDC config in total — six Go, three TS (Glouton, Ardoise, Perception), plus
Opus on better-auth. The TS siblings are out of scope for this repo but their issuer URL is not.

---

## 10. Repo conventions

Same as `tronc` and `caisse`:

- `scripts/check.sh` — gofmt, vet, `go test -race`, golangci-lint. Depends on nothing but a
  `go`, and is not invoked through mise on purpose.
- `.githooks/pre-push` runs it. Enable with `mise run hooks`.
- CI on Go 1.24 exactly — the floor the module documents — plus a PostgreSQL service once
  `porte/pg` has tests. **`.github/workflows/ci.yml` is deliberately not committed yet**: on a
  module with no packages, `go vet ./...` and `go test ./...` exit non-zero, so it would be red
  from the first commit for no reason. Copy it from `caisse` with the first package, changing
  the database env var to `PORTE_TEST_DATABASE_URL`.
- For the same reason, do not run `mise run hooks` until the first package exists — the
  pre-push gate would reject every push. The hooks are opt-in and inactive until enabled.
- Docs follow `~/Projects/Facile/Wiki/DOCS-STANDARD.md`: `README.md` plus `docs/` with
  `architecture.md`, `configuration.md`, `development.md`, `api.md`. English, no badges, no
  emoji.
- Semver from `main`. While on `v0`, a breaking change bumps the minor.
- Record decisions in `CHANGELOG.md` with their reasoning, as `caisse` does — the reasoning is
  the part that stops a future session from undoing a deliberate choice.

---

## 11. First step

Not code. Read the six `modules/auth/` implementations and diff them properly — `oidc.go`,
`service.go`, `middleware/auth.go` — then write the frozen contract of §5 as Go types and get
it reviewed before anything is built on top of it.

The rest is extraction. This part is the one that is expensive to get wrong.
