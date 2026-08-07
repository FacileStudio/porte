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
Sablier**. Each has the same 6 files under `apps/api/modules/auth/` plus `internal/authcrypto/`.
Journal has `authcrypto` and sessions but no OIDC at all. Capsule has no auth by design.

Measured 2026-08-07, `modules/auth/` only:

| App | total | `oidc.go` | `service.go` | `types.go` |
|---|---|---|---|---|
| Sablier | 664 | 162 | 314 | 27 |
| Courrier | 766 | 164 | 336 | 27 |
| Nuage | 761 | 169 | 373 | 35 |
| Agenda | 779 | 180 | 351 | 27 |
| Vision | 839 | 161 | 367 | 46 |
| Plume | 969 | 224 | 390 | 48 |

`types.go` is **byte-identical in three of the six** (Courrier, Agenda and Sablier share one
hash). `diff Nuage/oidc.go Sablier/oidc.go` is 27 lines out of ~165 — roughly 85% identical,
which is the number that justifies the extraction. Plume is the outlier at both ends because it
carries the CLI exchange flow (§5b).

`internal/oidcavatar/` — HTTPS validation, private-IP/SSRF rejection, download, store — is
copy-pasted in six apps as well, and has drifted **further than the auth code**: six files, six
distinct hashes, only Courrier and Sablier matching. It is a security guard, so this is the worst
place in the suite for six divergent copies.

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
| The old `Porte` repo → `authentik-config` | 93 lines of Authentik policy scripts. It frees the name. **Renamed locally 2026-08-07. There was never a GitHub repo for it — no remote, no commits — so nothing to rename there.** ~~And it has no reason to grow~~ — **wrong, corrected 2026-08-07**: the scope mapping that emits the `roles` claim (§5c) is server-side Authentik Python, so it belongs there next to the two existing expression policies. `authentik-config` is now the home of the claim contract's producing half |
| **`porte` carries authorization data, owns no policy** | Authentik decides *who has which role*; the app decides *what a role may do*; `porte` owns only the transport and the freshness in between. The three role models in production (`is_admin` + first-user-admin, Vision's workspace roles, the TS `USER`/`ADMIN` enum) are product decisions, not drift — a library that arbitrated them would be routed around by the second app. See §5c |
| **The claim contract is a flat `roles` array, produced per-provider** | Chosen over parsing group names (`facile-nuage-admin`) and over a nested per-app JSON claim. Each Authentik provider gets a scope mapping emitting `{"roles": ["admin"]}` already filtered and stripped for that app — namespacing and least privilege for free, no parsing in Go, and the one moving part lives in Authentik where it is configuration rather than code. Decided 2026-08-07 |
| **Back-channel logout is in v0.1** | Authentik has shipped it since 2025-10, and their docs are explicit that it is the *only* way a downstream app learns a session was terminated administratively. One endpoint in `porte`, one URL per Authentik application, and deactivating a user drops them from all seven apps in seconds. Highest value-to-effort item in this document |
| A future in-house IdP gets a new name, chosen when built | Naming a project you have not decided to build is a free commitment. Right register when it comes: institutions that issue identity papers — `consulat`, `préfecture`, `mairie` |
| Rebuilding Authentik is **not** decided | `porte`'s value does not depend on it. "Zéro dépendance cloud" does not apply — Authentik is already self-hosted on la ruche. Reopen the question only when `porte` runs on all seven apps, the OIDC contract has been stable for months, and something concrete is blocked by Authentik |
| Forced logout of production users is acceptable | User decision, 2026-08-07. This removes the whole backward-compatible session migration problem: one canonical session model, no dual-read, no cookie compatibility shims |
| Password hashing is already settled | All seven Go apps use argon2 today. No hash migration needed. (~~Journal carries bcrypt alongside argon2~~ — checked 2026-08-07: the only bcrypt hit is a test fixture string in `crypto_test.go`. Journal is argon2-only. Closed) |
| **Browser sessions ride an `HttpOnly` cookie, not `localStorage`** | Today the callback hands the token via URL fragment and the SvelteKit apps store it in `localStorage` — one XSS reads every token (RFC 9700, OWASP session cheat sheet). The suite's mono-container topology (P1b: same-origin `/api` behind Traefik, SPA served by `tronc/spa`) makes `HttpOnly; Secure; SameSite=Lax` cookies free. Bearer stays for CLIs and API clients; the middleware accepts both. Forced logout is already accepted, and the frontends are already being rewritten — this train does not pass twice. Decided 2026-08-07 |
| **`porte/pg` ships default identity tables; `UserStore` stays the escape hatch** | The six `schemas/user.go` share 12 byte-identical columns plus 0–4 business ones — the identity/profile split already exists, hand-written six times. Owning the shape once is what makes `facile_id`, `updated_at` (P4.3) and the `sub` fix land once instead of six times. Supabase (`auth.users`/`public.profiles`) and Ory Kratos both converge on the same boundary. Provided, never imposed — the `caisse` pattern. Decided 2026-08-07 |
| **OIDC account matching keys on `(provider, subject)`, never on email** | All six apps match by email today (`Where("email = ?")`) and no schema stores `sub`. Email is mutable in Authentik: an email change silently orphans the account in six apps; a deleted-then-recreated IdP account silently inherits the old one. This is a live security bug, wiki: `bugs/facile-oidc-email-matching.md`. Decided 2026-08-07 |
| **Identities are a separate table from users, from v0.1** | v0.2 explicitly plans local password *and* OIDC on the same human — one credential column set on the user row cannot represent that. `porte_identities(provider, subject)` also models "Login with Google" as a config change instead of a schema break, which client projects will want. Wire a single provider in v0.1; design the table for several. Decided 2026-08-07 |
| Pilot is the e-commerce demo + Nuage | Comptoir does not exist (checked 2026-08-07 — not locally, not in the org). A greenfield demo forces the works-outside-the-suite test on day one; Nuage is the extraction source, so the most honest feedback on fit |

---

## 4. Scope

### v0.1 — OIDC only

The identical part, extracted and hardened. No local password: apps that still need
email/password keep their own code in parallel for now, and lose roughly 60% of their auth
code rather than 100%.

In scope for v0.1, beyond the routes (all three decided 2026-08-07):

- **`oidcavatar`** — the HTTPS-validation / private-IP / SSRF guard. Six distinct hashes exist
  across the apps today; this is the file where drift is a security bug rather than cosmetics.
  The ROADMAP (task 3.4, exit criterion "exists exactly once") already required it; an earlier
  revision of this spec cited it as evidence but left it out of scope. That was the mistake.
- **`POST /auth/oidc/exchange`** — Plume's one-time-code CLI flow, generalized. Plume stores
  pending codes in a `sync.Map`, which dies on redeploy and breaks at two replicas. `porte`
  stores them in `porte_login_codes` (TTL 60s, single-use, hashed like sessions). Six CLIs
  need this; see §5b.
- **Cookie session issuance** — the callback sets the session cookie instead of putting the
  token in the URL fragment. See §5, Sessions.
- **Back-channel logout** — `POST /auth/backchannel-logout`, so an administrative deactivation
  in Authentik actually reaches the apps. See §5c.
- **Role claims, optional** — the `roles` claim, its startup guard and its refresh TTL. Off
  unless configured; no app reads claims today, so nothing regresses by leaving it off. See §5c.

### v0.2 — local password

`register`, `login`, `me`, `password`, argon2 via the extracted `authcrypto`. Blocked on
reconciling the drift in §2 and the role model in §7.

Note for client projects: v0.2 is where `porte` starts serving **two user populations** — staff
logs in through SSO, end customers (an e-commerce site's buyers, who will never have an
Authentik account) through email/password or a second OIDC provider. `porte_identities` is
designed for that from v0.1 even though v0.1 wires only one provider.

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
GET  /auth/oidc/callback   sets session cookie, 302 to OIDC_SUCCESS_URL   no auth
POST /auth/oidc/exchange   one-time code → bearer token (CLI path)    no auth, code required
POST /auth/logout          {"logged_out": true}, clears the cookie    session required
POST /auth/sync-profile    refresh profile from the IdP               session required
POST /auth/backchannel-logout   IdP-initiated session kill            logout token, no session
```

Scopes requested: `openid email profile offline_access` — unchanged, plus the scope carrying
`roles` when claims are enabled (§5c). `offline_access` is already requested by every app today,
which is what makes silent claim refresh possible without a second login.

### Sessions — one model, two transports

Opaque token, generated randomly, **stored hashed** (the existing `authcrypto.NewToken` /
`HashToken` pair). Keep this — it is stateful by design, revocable, and already what all six do.

What changes (2026-08-07) is how the browser carries it:

- **Browser: `HttpOnly; Secure; SameSite=Lax` cookie**, set by the callback. The token never
  appears in a URL, never touches `localStorage`, and the frontends' token-handling code is
  deleted rather than migrated — `fetch` gains `credentials: 'include'` and that is all.
  CSRF: `SameSite=Lax` plus a custom-header check on mutating routes.
- **CLI and API clients: `Authorization: Bearer …`**, unchanged.

The middleware accepts both, cookie first. Same table, same hash, same revocation.

The sessions table carries `label`, `created_at` and `last_used_at` — absent today, and the
reason no app can show "your active sessions" or revoke one token without revoking them all.
`label` is what turns a session row into a named API token (§5b).

`porte` owns the sessions table and ships `porte/pg` for it, following `caisse/pg`: an
interface plus a `database/sql` implementation, so no ORM is forced on consumers.

### 5b. CLI login and API tokens

One flow, one table, both use cases.

**Interactive CLI login** — the pattern `gh auth login` and Claude Code use: the CLI opens
`/auth/oidc?flow=cli` in a browser, the user logs in through the IdP, and the callback — instead
of setting a cookie — issues a **one-time code** (stored hashed in `porte_login_codes`, TTL 60s,
single-use). The success page displays it for copy-paste; a CLI that started a loopback listener
receives it directly and the paste is the fallback. The CLI exchanges it at
`POST /auth/oidc/exchange` for a bearer token. This is Plume's existing flow with the `sync.Map`
replaced by the database, so it survives redeploys and replicas.

**API tokens** are not a separate mechanism: an API token is a session row with a `label`, a
long or absent expiry, and `last_used_at` for auditability. Courrier and Agenda have already
each grown their own `ApiToken` types — same drift pattern as everything else in this document.
`porte`'s session store exposes create/list/revoke-by-id; the HTTP routes for "personal access
tokens" stay app-side in v0.1 (they are product surface), backed by the store.

Deferred, explicitly: token **scopes** (a `porte` token is currently as powerful as its user)
and the full RFC 8628 device flow delegated to Authentik, which supports it natively — that
upgrade replaces the copy-paste UX with `gh`-style `user_code` entry and belongs in v1.x.
Store refresh material in the OS keychain, never a JSON file — a CLI-side concern, documented
here because six CLIs will read this spec.

### 5c. Claims, roles, and freshness

Authorization has three layers, and conflating them is how auth libraries turn into frameworks:

| Layer | Question | Owner |
|---|---|---|
| Assignment | is saravenpi an admin of Nuage? | **Authentik** — groups and attributes |
| **Transport + freshness** | how the app learns it, and re-learns it | **`porte`** |
| Policy | what may an admin actually do? | **the app** |

`porte` is the middle row, exactly as it is for authentication. It decides nothing.

Two facts from source, 2026-08-07, that make this a clean slate: every app requests
`openid email profile offline_access` and **no app requests or reads a `groups` claim**. Nothing
to migrate, and refresh tokens are already in hand.

**The claim.** A flat array of opaque strings, in a `roles` claim:

```json
{ "roles": ["admin"] }
```

Produced by a per-provider scope mapping in Authentik, already filtered and stripped for that
application — so Nuage's token never mentions Sablier's roles. The alternatives were parsing
group names (`facile-nuage-admin` — an implicit contract in strings, which is what drifts) and a
nested `{"facile": {"apps": {...}}}` claim (explicit but needs parsing in six apps). A flat array
per provider gets namespacing and least privilege for free while keeping the Go side trivial.
`porte` exposes the strings; it never assigns them meaning.

The producing half — a small Python scope mapping, parameterised by app slug — lives in
`authentik-config` alongside the two existing expression policies.

**The startup guard, and why it exists.** authentik's docs carry a specific trap: group-based
authorization needs the scope attached to the provider's property mappings *and* requested by
the client, and if either half is missing **the rules silently deny everyone**. A silent deny in
the auth path is the worst failure mode there is. So when claims are enabled, `porte` verifies at
startup that the scope was granted and a `roles` claim actually arrived, and refuses to boot with
a message naming the missing half. Written once, six apps protected.

**Freshness — the part that is actually hard.** Sessions are opaque and long-lived; an Authentik
group change does not reach them. For comparison, Entra's group-membership changes take up to a
day to apply without a dedicated mechanism, which is not acceptable for *removing* a right.
Three mechanisms, and v0.1 ships the first two:

1. **TTL on claims.** `profile_synced_at` already exists to rate-limit profile refreshes; the
   same pattern covers claims, refreshed lazily against the IdP using the refresh token every app
   already holds. Short TTL, no new infrastructure, covers the routine case.
2. **Back-channel logout.** `POST /auth/backchannel-logout` validates the logout token and
   deletes that user's sessions. This is the security-critical case — deactivation, admin
   session termination — and per authentik's own documentation it is the only mechanism that
   covers it. One endpoint here, one URL per application there.
3. **Nook**, later. A group-change event invalidating cached claims is the suite-native version
   and composes with P4, but 1 and 2 cover the need; do not build it for this.

Because sessions are opaque and claims are stored server-side (`porte_identities.claims`, JSONB),
there is no token-size ceiling — the *group overage* problem that forces Entra to invent a
`hasgroups` claim and a directory round-trip simply does not arise here.

**What `porte` hands the app, and where it stops:**

```go
id, _ := porte.From(ctx)
id.HasRole("admin")   // typed, parsed, kept fresh — meaning is the app's business
```

No `RequireRole` middleware for IdP roles, and no policy engine. The app writes its own guard in
five lines, which is the smaller of the two options §7 Q4 posed and the one that keeps all three
production role models working untouched.

**Do not confuse this with `porte/espace` (v0.3).** Space membership is app-local data — the
spaces live in the app's own database — so `espace.RequireRole(spaceID, role)` resolves
membership, not IdP claims. Two different axes that must not be merged: a claim says what
Authentik thinks of you globally; a membership says what this app's data says about you in one
space.

**What not to build.** If centralised fine-grained authorization ever becomes a real requirement,
do not invent an API for it: the OpenID **AuthZEN Authorization API 1.0** went Standards Track in
March 2026 with wide vendor interop, and Keycloak already ships experimental support. `porte`'s
job in that world is to be a good PEP, never a PDP. That is a v2 conversation, recorded here so
nobody starts a home-grown authorization service in the meantime.

**The gap claims will never close.** A claim describes only the user who just logged in — it
never tells an app who *else* exists. Today every app knows only the users who have signed in at
least once, which is why "share this file with a colleague" and "invite someone to a space" have
no directory to draw on. The standard answer is authentik's **SCIM provider** (backchannel
provisioning, pushed on change plus an hourly resync), which would give each app a local, fresh
copy of users *and* groups. Deliberately **not** in scope: it is a second protocol and an endpoint
per app, and mechanisms 1–2 already solve freshness. Recorded as the known direction for the day
an invite screen needs to list people who have never logged in.

### The app owns its *profile* — `porte/pg` offers the identity tables

An earlier revision said "`porte` must never own the users table — apps have genuinely
different user columns." Read against source, that premise is false: the six `schemas/user.go`
share **12 byte-identical columns**, plus 0 (Courrier, Agenda, Vision) to 4 (Sablier) business
columns. The identity/profile split already exists in every app, hand-written.

The shared core, identical in all six: `id`, `email` (uniqueIndex), `name`, `avatar_url`,
`avatar_source`, `oidc_picture_url`, `password_hash`, `oidc_access_token`, `oidc_refresh_token`,
`oidc_token_expiry`, `profile_synced_at`, `created_at`. Everything else, per app:

| App | Business columns beyond the core |
|---|---|
| Courrier, Agenda | none — **byte-identical files** |
| Vision | none (roles live in `workspace_members`) |
| Plume | `reminder_interval_days` |
| Nuage | `color`, `is_admin` |
| Sablier | `color`, `rate`, `rate_type`, `workday_hours` |

Note what is *missing* from the core: no `updated_at` anywhere (ROADMAP P4.3), no `facile_id`
outside Nuage (P4.1), and **no `sub`** (§6.1). Five of the twelve core columns — the `oidc_*`
group plus `profile_synced_at` — are `porte` plumbing that has no business being in an app's
domain table at all.

So `porte/pg` ships, as the *default* implementation of the interfaces:

```
porte_users        id, facile_id, email (unique), email_verified, name,
                   avatar_url, avatar_source, created_at, updated_at
porte_identities   user_id, provider, subject, password_hash,
                   access_token, refresh_token, token_expiry, synced_at
                   UNIQUE(provider, subject)
porte_sessions     token_hash PK, user_id, label, created_at, last_used_at, expires_at
porte_login_codes  code_hash PK, user_id, expires_at
```

The app keeps its business columns in its own `user_profiles` (or wherever it likes),
`user_id PK REFERENCES porte_users(id)` — existing FKs keep pointing at the same `int64`.
Schemas are constants applied through the app's own migrations, never at boot (`caisse/pg`
precedent). Matching on callback: `(provider, subject)` lookup; fallback linking by email only
when `email_verified` is true.

The interface remains the escape hatch, and is all `porte` itself compiles against:

```go
type UserStore interface {
	UpsertFromOIDC(ctx context.Context, claims Claims) (userID int64, err error)
}
```

An app with an exotic user model implements it and ignores `porte/pg` entirely. Fields the
current implementations write on upsert, as a checklist for `Claims`: subject, provider, email,
email_verified, name, picture URL, plus `avatar_url` / `avatar_source` / `oidc_picture_url` /
token material / `profile_synced_at`. `profile_synced_at` exists to rate-limit profile
refreshes — keep it.

**`UpsertFromOIDC` has side effects in real apps, and the interface must tolerate that.** Nuage's
version assigns a display colour through `usercolor.NextAvailable` and makes the first user ever
created an admin (`IsAdmin: userCount == 0`). That logic is product behaviour, it stays app-side,
and it is precisely why the app implements this method rather than `porte` owning the write.
`porte` calls it once per successful callback and cares only about the returned id.

### Roles are a hook, not an enum

`porte` must not arbitrate the role model. Today: Nuage uses `IsAdmin bool` with first-user-
admin, Vision uses workspace-scoped roles, the TS family uses a `USER`/`ADMIN` enum. All three
have to keep working. How the IdP's view of a user reaches the app without `porte` interpreting
it is §5c.

---

## 6. Security — fix these while extracting

Read from `Nuage/apps/api/modules/auth/oidc.go` on 2026-08-07. The existing flow is decent and
should be preserved, with three additions. Writing them once here instead of six times is a
concrete argument for the library.

**Already good, keep it:** `state` is random per request, stored in a cookie that is `HttpOnly`,
`Secure` when the success URL is https, `SameSite=Lax`, TTL-bounded, compared on callback and
cleared immediately after. The ID token is verified through `go-oidc`'s verifier.

**Missing — add:**

1. **Match on `sub`, not email — the most severe item on this list.** All six apps upsert with
   `Where("email = ?", email)` and store no `sub`. Email is mutable in the IdP: a rename orphans
   the account in six apps silently; a deleted-then-recreated IdP account inherits the old one.
   Fixed structurally by `porte_identities(provider, subject)` in §5. During extraction, also
   verify every app actually enforces `email_verified` — unverified email plus email matching is
   an account-takeover primitive.
2. **PKCE (S256).** `AuthCodeURL(state)` is called with no code challenge. Add
   `oauth2.S256ChallengeOption`, with the verifier carried in a cookie alongside the state.
3. **Nonce.** No nonce is generated or checked against the ID token claim. Generate one per
   request, carry it with the state, and verify it after `Verify` returns.
4. **Constant-time state comparison.** The check is a plain `!=`. Use
   `subtle.ConstantTimeCompare`. Free, and removes the question entirely.
5. **Kill the `localStorage` token.** Today the callback puts the token in the URL fragment and
   the frontend stores it in `localStorage` — one XSS reads it (RFC 9700 §the-obvious). The
   cookie transport in §5 removes both halves at once.

**Non-negotiable:** do not hand-roll protocol or crypto. `go-oidc` for verification,
`golang.org/x/oauth2` for the flow, `argon2` for hashing. This is the one place custom code is
unacceptable.

---

## 7. Open questions — settle before coding the affected part

1. ~~**CLI token flow.**~~ **Settled 2026-08-07** — read Plume's implementation: the callback
   parks a one-time code in a `sync.Map`, the CLI exchanges it. Right flow, wrong store (dies on
   redeploy, breaks at two replicas). v0.1 owns it, DB-backed. See §5b.
2. **`/auth/me` and `/auth/password`** — v0.2 of `porte`, or permanently app-side? They touch
   the app's user columns, which argues app-side.
3. ~~**Journal's bcrypt.**~~ **Settled 2026-08-07** — the only bcrypt hit in Journal is the
   fixture string `"$2y$n$nope"` in `authcrypto/crypto_test.go`. Argon2-only. Non-issue.
4. ~~**Role hook shape.**~~ **Settled 2026-08-07 — the smaller option.** Claims ride typed but
   uninterpreted on the identity; the app writes its own guard. `porte` ships no `RequireRole`
   for IdP roles and no policy engine. Full design, including the freshness mechanisms and the
   startup guard, in §5c.
5. **CSRF header convention** — which custom header the SvelteKit clients send on mutating
   requests, so the cookie transport's second lock is uniform across the suite. One name,
   decided once, before the first frontend adopts the cookie.
6. **Claim refresh TTL** — a concrete number for §5c mechanism 1. Short enough that a revoked
   role stops mattering quickly, long enough not to hammer the IdP on every request. Pick it
   with `profile_synced_at`'s existing interval in view, so there is one refresh cadence and not
   two.

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
- Go floor 1.24, matching `caisse` and the `tronc` root module. **Check before committing:**
  `tronc/migrate` already declares `go 1.25.7`, and Phase 2 moved the apps to Go 1.25, so the
  floor may need to be 1.25 for consistency. Decide once, and make `.github/workflows/ci.yml`
  pin the same number.

---

## 9. Validation and rollout

**Before tagging v0.1.0:** prove it on the **e-commerce demo** (greenfield, no live sessions to
break, and it forces the works-outside-the-suite test — a non-Authentik `OIDC_ISSUER` — on day
one) and **Nuage** (the extraction source, so the most honest feedback on whether the
abstraction fits). This is the sequence that made `tronc` right — written, proven on one,
rolled out after. *(An earlier revision named Comptoir here; Comptoir does not exist.)*

The cookie transport touches the six SvelteKit frontends as well as the six backends — the one
place this plan costs more than plain extraction. It rides the frontend rewrite (F track), and
forced logout is already accepted, so the marginal cost is one deleted token-handling file per
frontend.

**Then** the remaining five, in one pass each. Change `OIDC_ISSUER` to `sso.facile.studio` in
the same commit that adopts the library: the app's env is already being edited, so it costs one
extra line. Done separately it is a second tour of ten repos.

Ten backends carry OIDC config in total — six Go, three TS (Glouton, Ardoise, Perception), plus
Opus on better-auth. The TS siblings are out of scope for this repo but their issuer URL is not.

**Perception is a consumer already waiting.** Its Go rewrite deliberately built a seam for this
library: `apps/api/internal/identity/` holds an `Authenticator` interface that feature modules
depend on, `modules/auth` is reachable from `main.go` alone, and `apps/api/seam_test.go` is an
architecture test that *fails* if any other package imports the auth module. Its `ROADMAP.md` §7
says the adoption is "delete `modules/auth`, add the dependency, construct it in `main.go`, done."
Treat it as the third pilot: it is the only repo whose structure will tell you whether the
interface shape is right, because it was designed against the idea rather than extracted from it.
(That seam was written under the working name `sésame`; renamed to `porte` on 2026-08-07.)

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

## 12. Prior art, and what it actually says

Consulted 2026-08-07. Listed because several of these argue *against* parts of this document,
and a future session should be able to check the reasoning rather than trust it.

**On owning the identity table.** [Supabase](https://supabase.com/docs/guides/auth/managing-user-data)
splits `auth.users` (owned by GoTrue) from `public.profiles` (owned by the app) — the same
boundary as §5, validated at scale. Read its *reasons* critically though: it cites "Supabase does
not allow adding columns to auth.users" and "the auth schema is not publicly accessible", which
are constraints of a hosted multi-tenant service, not design conclusions. The shape transfers;
the argument does not, so §5 makes its own.
[Ory Kratos](https://www.ory.com/docs/kratos/manage-identities/identity-schema) reaches the same
boundary from the opposite direction: identity owns traits, and the guidance is to "avoid complex
identity schemas" and keep app-specific data out.
[better-auth](https://better-auth.com/docs/concepts/database) tests the other road — one owned
table extended via `additionalFields` — and the friction is documented: you extend your own schema
to match, and [custom tables need a plugin](https://github.com/better-auth/better-auth/discussions/6717).
That is the in-house precedent too, since Opus and Hottake run it.

**The honest counter-argument.** [Beekeeper](https://www.beekeeperstudio.io/blog/one-to-one-database-relationships-complete-guide)
and [O'Reilly](https://www.oreilly.com/library/view/microsoft-sql-server/9780133408539/ch34lev2sec4.html)
are firm that needless 1:1 splits of closely-related data are a mistake. They are right, and it is
why §5 justifies the split as a **module boundary**, never as normalisation — there is no
performance win in separating 12 columns from 3, and claiming one would be dishonest.

**On account vs identity.** [Red-gate](https://www.red-gate.com/blog/user-authentication-module/) —
keep account and identities separate so one human can hold several authentication factors. That is
where `porte_identities` comes from.

**On sessions in the browser.** [OAuth 2.0 for Browser-Based Apps](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/12/),
[OAuth 2.1 / RFC 9700](https://aembit.io/blog/oauth-2-1-guide-migration-security/) and the
[OWASP Session Management cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
agree: never `localStorage`; `HttpOnly; Secure; SameSite` cookies, or a BFF. The suite's
mono-container already provides the same-origin backend that pattern needs.

**On CLI login.** [RFC 8628](https://www.rfc-editor.org/info/rfc8628/) plus two practitioner
write-ups ([abgeo](https://www.abgeo.dev/blog/cli-authentication-the-right-way/),
[Logto](https://dev.to/logto/getting-cli-authentication-right-the-complete-guide-to-all-4-methods-1mnf)):
device flow by default, refresh material in the OS keychain rather than a dotfile, `gh auth login`
as the reference implementation.

**On claims and freshness.**
[authentik property mappings](https://docs.goauthentik.io/add-secure-apps/providers/property-mappings/)
— including the trap where a half-configured scope silently denies everyone;
[authentik back-channel logout / SLO](https://goauthentik.io/blog/2025-10-21-authentik-now-supports-single-logout/)
— the only mechanism covering administrative termination;
[Entra continuous access evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation)
— why an unrefreshed group membership can be a day stale, and the *group overage* problem that
server-side claim storage avoids entirely.

**On what not to build.** [AuthZEN Authorization API 1.0](https://openid.github.io/authzen/) went
Standards Track in March 2026, with [Keycloak shipping experimental support](https://www.keycloak.org/2026/05/authzen-as-experimental-feature).
If centralised fine-grained authorization is ever needed, `porte` is a PEP against that, never a
bespoke PDP. And [authentik's SCIM provider](https://docs.goauthentik.io/add-secure-apps/providers/scim/)
is the answer to the directory problem claims cannot solve — noted, deliberately unbuilt.

**On library design.** [authboss](https://github.com/volatiletech/authboss) ("plug it in, configure
it, start building") for the ambition, [goth](https://github.com/markbates/goth) for the shape:
small interfaces, implementations provided.

---

## 11. First step

Not code. Read the six `modules/auth/` implementations and diff them properly — `oidc.go`,
`service.go`, `middleware/auth.go` — then write the frozen contract of §5 as Go types and get
it reviewed before anything is built on top of it.

The rest is extraction. This part is the one that is expensive to get wrong.
