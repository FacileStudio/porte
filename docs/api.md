# porte — API

Every exported symbol, package by package. The reasoning for each decision is in
[SPEC.md](../SPEC.md) §5.

| Package | What it is | Depends on |
|---|---|---|
| `porte` | The frozen contract: types, interfaces, wire shapes. No behaviour | the standard library |
| `porte/oidc` | The engine: the flow, the seven routes, the middleware, the avatar guard | go-oidc, oauth2, tronc, chi |
| `porte/pg` | The identity tables and the four stores over them | `database/sql` |

**The contract package depends on nothing outside the standard library, and that is a constraint
rather than a coincidence.** An app's stores and domain code compile against plain types and
never see `go-oidc`, `golang.org/x/oauth2` or a database driver. It is why `Claims` carries plain
fields and `TokenSet` exists instead of an `*oauth2.Token`, and it is why the engine is a
separate package rather than living here: only an app's `main.go` imports `porte/oidc`.

## Errors

| Symbol | What it is |
|---|---|
| `ErrNotFound` | A store found no row. Stores are implemented by consumers, so the contract needs its own sentinel rather than leaking `sql.ErrNoRows` or a GORM error across the boundary |
| `ErrCodeConsumed` | A login code was already exchanged. Separate from `ErrNotFound` because a replayed code is an attack and an unknown one is a typo |

## Routes

Path constants, so an app and its frontend cannot disagree about a string.

| Symbol | Path |
|---|---|
| `RouteConfig` | `GET /auth/config` |
| `RouteLogin` | `GET /auth/oidc` |
| `RouteCallback` | `GET /auth/oidc/callback` |
| `RouteExchange` | `POST /auth/oidc/exchange` |
| `RouteLogout` | `POST /auth/logout` |
| `RouteSyncProfile` | `POST /auth/sync-profile` |
| `RouteBackchannelLogout` | `POST /auth/backchannel-logout` |

The first three are served at these exact paths with these exact response shapes by all six Go
apps today, which is what makes them safe to freeze.

## Configuration

`Config`, its constants and defaults are documented in [configuration.md](configuration.md).

| Method | Returns |
|---|---|
| `Enabled() bool` | Whether an issuer is configured at all |
| `ClaimsEnabled() bool` | Whether to request and verify the roles claim |
| `Scopes() []string` | The scopes to request, with `ClaimsScope` appended when set |
| `Validate() error` | Names **every** missing variable at once, so a misconfiguration takes one fix |
| `Resolved() Config` | A copy with zero durations replaced by their defaults |
| `HTTPS() bool` | Whether the app is served over TLS, read off `RedirectURL` or `SuccessURL` |
| `IdleTimeout() time.Duration` | The browser session idle window: zero `SessionIdleTTL` means the default, negative means disabled |

`HTTPS` exists so the `Secure` cookie attribute has a source that a proxy cannot revoke. It
overrides the per-request `X-Forwarded-Proto` test upward and never downward.

## Wire shapes

| Type | Route | Fields |
|---|---|---|
| `ConfigResponse` | `/auth/config` | `sso_only`, `oidc_enabled` |
| `ExchangeRequest` | `/auth/oidc/exchange` | `code` |
| `ExchangeResponse` | `/auth/oidc/exchange` | `user_id`, `token` |
| `LogoutResponse` | `/auth/logout` | `logged_out` |
| `SyncProfileResponse` | `/auth/sync-profile` | `synced` |

`ExchangeResponse.UserID` is a **string** on the wire while `Identity.UserID` is an `int64` in
Go. That is deliberate: to a CLI the field is an opaque identifier, so changing its JSON type
breaks clients and buys nothing.

`SyncProfileResponse.Synced` is false when the call was a no-op because the rate limit had not
elapsed. It is not an error.

## Identity

`Identity` is what an authenticated request carries.

| Field | Type | What it is |
|---|---|---|
| `UserID` | `int64` | Matches `porte_users.id` and the existing `int64` foreign keys |
| `Email` | `string` | |
| `EmailVerified` | `bool` | |
| `Name` | `string` | |
| `Roles` | `[]string` | What the IdP says, for this app, as of the last refresh |
| `SessionID` | `int64` | The session row this request authenticated against |
| `RolesSyncedAt` | `time.Time` | When `Roles` were last refreshed |

| Function | What it does |
|---|---|
| `HasRole(role string) bool` | Exact match. The claim is already scoped per application, so there is no prefix to parse |
| `HasAnyRole(roles ...string) bool` | Any of them |
| `WithIdentity(ctx, Identity) context.Context` | The middleware calls it; apps normally only do in tests |
| `From(ctx) (Identity, bool)` | False on an unauthenticated request |

`UserID` being an `int64` is a deliberate break from the decimal string the apps pass around
today. The conversion moves to the edge instead of being repeated in every handler.

`From` returning a typed value replaces the current
`Authenticate(ctx, string) (string, any, error)` followed by an
`interface{ GetEmail() string }` assertion — a runtime failure mode sitting in the auth path of
six apps.

### Where porte stops

```go
id, _ := porte.From(ctx)
if !id.HasRole("admin") {
	// the app's guard, five lines, the app's rules
}
```

There is no `RequireRole` for IdP roles and no policy engine. The three role models in
production — a bool column with first-user-admin, workspace-scoped roles, and a `USER`/`ADMIN`
enum — are product decisions. A library that arbitrated between them would be routed around by
the second app that adopted it.

Do not confuse this with `porte/espace` (v0.3): space membership is app-local data, so
`espace.RequireRole(spaceID, role)` resolves membership, not claims. A claim says what the IdP
thinks of you globally; a membership says what this app's data says about you in one space.

## Claims

`Claims` is what the provider asserted during a callback, normalised. It is the only `porte`
type a `UserStore` implementation has to understand.

`Provider` and `Subject` are the account matching key. Never email: email is mutable in the IdP,
so matching on it lets a rename orphan an account and a delete-then-recreate inherit one.

`Email`, `EmailVerified`, `Name`, `PreferredUsername`, `GivenName`, `FamilyName`, `Picture`
carry the profile. `Roles` is absent unless `ClaimsScope` is set and the provider emitted it.
`Tokens` is a `TokenSet`.

`AvatarURL` is filled by `porte`, not by the provider: when an `AvatarStore` is wired, the
picture is fetched through the SSRF guard and stored before the upsert runs, so the app writes
the final URL in the same statement as the name and the email. `AvatarKey() string` is the
opaque, stable key that avatar was filed under.

`DisplayName() string` is the precedence every app already implements: `name`, then
`preferred_username`, then given and family names joined. Empty when none was asserted.

### TokenSet

`AccessToken`, `RefreshToken`, `Expiry` — plain strings and a time, so the store boundary does
not depend on `golang.org/x/oauth2`.

Two apps encrypt these columns at rest today and four store them in the clear. `porte` hands the
store plaintext and the store decides: encryption at rest is a deployment property, and `porte`
has no key management to offer.

### StoredIdentity

One row of `porte_identities`: a single way one human authenticates. A human may hold several —
an OIDC subject and a local password are two rows, not two columns, which is what makes v0.2 a
configuration change rather than a schema break.

`RolesStale(now, ttl) bool` reports whether the cached claim should be refreshed. A claim that
was **never** synced is stale: a missing refresh must not read as fresh.

Because the claim is cached server-side and sessions are opaque, there is no token size ceiling
here — the group overage problem that forces other stacks to invent a `hasgroups` claim and a
directory round-trip does not arise.

## Stores

Implement these, or use `porte/pg`. The interfaces are what `porte` itself compiles against.

### UserStore

```go
UpsertFromOIDC(ctx context.Context, claims Claims) (userID int64, err error)
```

The escape hatch, and the whole user-data surface. **It has side effects in real apps and the
interface tolerates that deliberately**: one app assigns a display colour on creation and makes
the first user ever created an admin. That is product behaviour, it stays app-side, and it is
exactly why the app implements this method instead of `porte` owning the write. `porte` calls it
once per successful callback and cares only about the returned id.

Match on `(Provider, Subject)`. Fall back to email **only** when `Claims.EmailVerified` is true —
an unverified email plus email matching is an account takeover primitive.

### IdentityStore

`Find(ctx, provider, subject)`, `Save(ctx, identity)`,
`MarkRolesSynced(ctx, provider, subject, at)`, `ListByUser(ctx, userID)`.

`Find` returns `ErrNotFound`. `Save` inserts or updates by `(Provider, Subject)`. It writes the
**whole row**, so it must only be called with an identity the caller holds the newest version of.
`ListByUser` returns every way a human can authenticate, which is what an account settings screen
needs.

`MarkRolesSynced` moves only the `roles_synced_at` stamp, and it exists because `Save` cannot do
that safely. When a role refresh fails, `porte` still records the attempt so a dead refresh token
is not retried on every single request — but the identity it is holding was read *before* the
refresh, and writing it back whole would restore the refresh token it had read over the one a
concurrent request may have just rotated in. A lost rotation locks the user out of every later
refresh. One column, one statement, no read-modify-write.

An app implementing `IdentityStore` over its own tables has to implement this fourth method too.

### SessionStore

`Create`, `Find`, `Touch`, `Delete`, `DeleteByUser`, `ListByUser`, `DeleteByID`, `DeleteExpired`.

Every method takes a **hash**, never a token. Keeping the plaintext out of the store interface
is what stops it reaching a log line or a query parameter.

`Find` must **not** filter on expiry. An expired session and a missing one are different
answers, and only the caller knows which error to return.

`DeleteByUser` is what back-channel logout calls. It is the only mechanism by which an
administrative deactivation in the IdP reaches an app that issued an opaque, long-lived session
of its own.

`DeleteByID` takes the user id as well as the session id, so a handler cannot revoke another
user's session by guessing an integer.

`Touch` should coalesce writes rather than issue one `UPDATE` per request.

### LoginCodeStore

`Create`, `Consume`, `DeleteExpired`.

`Consume` claims the code in one operation, so two exchanges racing each other cannot both win.
It returns `ErrCodeConsumed` when the code was already spent, and `ErrNotFound` when it never
existed — distinguishing a replay from a typo is worth one error value, because a code that was
valid a moment ago and is being presented a second time means either the CLI retried or somebody
else is holding it.

### AvatarStore

`Put(ctx, key, data, contentType) (avatarURL string, err error)` and `Remove(ctx, avatarURL)`.

`key` is an opaque, stable per-identity string — `Claims.AvatarKey()` — and **not** a user id.
The avatar is fetched and stored *before* `UpsertFromOIDC` runs, so no user id exists yet, and
the resulting URL rides into the upsert on `Claims.AvatarURL`. That ordering is what keeps the
whole callback to one write on the app's side. A stable key also means a re-sync overwrites
rather than accumulating one file per login, which is what the apps do today.

The fetch itself — HTTPS-only validation, private address rejection, size limit, content type
check — belongs to `porte` and exists once, because six divergent copies of an SSRF guard is the
one place in this suite where drift is a vulnerability rather than an inconsistency. Where the
bytes go is not `porte`'s business: one app writes them under a storage dir, another serves them
from object storage. `Remove` must be a no-op when the avatar is already gone.

## Sessions

`Session` carries `ID`, `TokenHash`, `UserID`, `Label`, `CreatedAt`, `LastUsedAt`, `ExpiresAt`.

One session model, two transports: an `HttpOnly` cookie in browsers, `Authorization: Bearer` for
CLIs and API clients. Same table, same hash, same revocation.

`Label` turns a session row into a named API token. Two apps have each grown their own separate
`ApiToken` type and table for exactly this, which is one more mechanism than the problem needs.

`LastUsedAt` is what makes a session list auditable. No app records it today, which is why none
of them can offer "your active sessions". It is also what the idle window reads.

| Method | What it does |
|---|---|
| `Expired(now) bool` | A zero `ExpiresAt` never expires — that is what a long-lived API token wants |
| `IsAPIToken() bool` | Whether the row was created as a named token rather than an interactive login |

`Expired` is the absolute lifetime only. A session that is still inside it but has gone unused
for longer than `Config.IdleTimeout()` also stops authenticating, and the middleware deletes the
row on the request that finds it rather than leaving a lookup to be paid on every replay of a
token that will never authenticate again. The window applies to the cookie transport only —
bearers are CLIs and API tokens, which are idle by design. See
[configuration.md](configuration.md).

`LoginCode` carries `CodeHash`, `UserID`, `ExpiresAt`, and `Expired(now) bool`.

The session is created **at exchange time**, not at callback time. An earlier revision carried a
`SessionID` here so the exchange would be a pure lookup; that cannot work, because the session
row stores only a hash, so handing the CLI a usable token later would mean keeping the plaintext
at rest. `Consume` is atomic, so a code still yields at most one session.

## Tokens

| Symbol | What it does |
|---|---|
| `NewToken() (string, error)` | 32 random bytes, URL-safe. Every credential porte issues |
| `HashToken(token) string` | The stored form. SHA-256, hex — the encoding all six apps already use, so their existing session rows keep authenticating |
| `SecureCompare(a, b) bool` | Constant-time comparison. Five of six apps compare the OIDC state with a plain `!=`; this is Plume's line, which was the one that was right |

SHA-256 is right here and argon2 is not: the input is 256 bits of entropy `porte` generated
itself, so there is no dictionary to slow down, and this runs on every authenticated request.

## porte/oidc

### Kit

`New(ctx, cfg, Deps) (*Kit, error)` performs discovery and returns the engine. A disabled config
is not an error — it returns a kit that serves `RouteConfig` and `RouteLogout` and authenticates
sessions, which is what an app running without SSO needs.

`New` is the boot path, so every detectable misconfiguration is detected there: a half-filled
environment, an unreachable issuer, a missing store, and a roles scope the provider does not
advertise.

| Method | What it does |
|---|---|
| `Mount(chi.Router)` | Registers the routes at the frozen paths, relative to that router |
| `RequireAuth(http.Handler) http.Handler` | Rejects unauthenticated requests |
| `Optional(http.Handler) http.Handler` | Attaches an identity when there is one, lets the request through either way |
| `Config() porte.Config` | The resolved configuration |
| `Enabled() bool` | Whether the OIDC routes are live |

`Deps` carries `Users`, `Identities`, `Sessions`, `Codes`, an optional `Avatars` and an optional
`Logger`. `porte/pg` implements all four.

`Mount` always registers `GET /auth/config` and `POST /auth/logout`; the OIDC routes and
`POST /auth/sync-profile` appear only when a provider is configured. Ending a session needs the
`SessionStore` that `New` requires either way, so gating it behind OIDC only forced an app
without SSO to keep a second logout handler answering a second response shape.

`Deps.ConfigExtra func() map[string]any` adds fields to `GET /auth/config`. Every app in the
suite serves a superset there — `allow_registration` in Journal, a legacy `password_auth` in
Jardin — and `porte` owns the path, so without this the app either drops its key or registers
the route twice and chi panics. `sso_only` and `oidc_enabled` are written over whatever the map
contains: the frontend decides on those two whether to draw a password form at all, and they
answer to the configuration alone.

### What the middleware accepts

The session cookie, then `Authorization: Bearer`. **Nothing else** — no query parameter, ever. A
credential in a URL lands in access logs, referrers and browser history, and the two cases that
genuinely needed one (`EventSource`, download navigations) are exactly what the cookie transport
serves for free.

On a cookie-authenticated **mutating** request the `X-Facile-CSRF` header must be present, with
any value. Bearer callers are exempt: nothing attaches a header on their behalf, so there is no
CSRF to defend against.

Over https the cookie is written and read under `__Host-session`, and the bare `session` is read
only when `Config.AcceptLegacyCookie` is set for a migration. Over plain http the bare name is
the only one a browser keeps, so it is the only one read. The reasoning is in
[configuration.md](configuration.md).

### What the routes answer with

`POST /auth/oidc/exchange` sets `Cache-Control: no-store`. It is `porte`'s token endpoint in
everything but name, and OAuth 2.1 §7.1 requires it of any response carrying a credential. The
back-channel logout endpoint and the CLI code page do the same.

`POST /auth/sync-profile` compares the `sub` in the UserInfo response against the stored subject
and answers 401 without writing anything when they differ. OpenID Connect Core §5.3.2 requires
that comparison and `go-oidc` does not make it — it fetches and parses, nothing more — so without
it a provider, or anything sitting between it and the app, can rewrite one user's profile with
another user's claims.

### FetchAvatar

`FetchAvatar(ctx, pictureURL) (data []byte, contentType string, err error)`.

The guard runs **in the dialer**, not before it. Every existing copy resolves the hostname,
checks the addresses, then calls `http.Get`, which resolves again — a DNS record that answers
publicly on the first lookup and privately on the second walks straight through. Checking at
connect time closes that window and covers redirects for free.

The subtle half of the address check is the IPv6 forms that embed an IPv4 address. `net.IP`'s own
predicates understand the plain forms and the IPv4-mapped one, so `64:ff9b::a9fe:a9fe` (NAT64)
and `2002:a9fe:a9fe::` (6to4) both reach `169.254.169.254` — the cloud metadata service this
guard exists for — while looking like ordinary public IPv6. So does the deprecated
IPv4-compatible `::a.b.c.d`. All three are unwrapped to the address they actually reach and
checked again. NAT64 is unwrapped rather than blocked outright, because on an IPv6-only host
every IPv4 destination, including every legitimate avatar host, arrives in that form.

The deny list covers the ranges those predicates do not: `100.64.0.0/10` (carrier-grade NAT),
the three TEST-NETs, `192.0.0.0/24`, `198.18.0.0/15`, `240.0.0.0/4`, `0.0.0.0/8`, the broadcast
address, and on the IPv6 side Teredo (`2001::/32`, which carries an embedded IPv4 nobody needs to
reach), `100::/64`, local-use NAT64 and the documentation prefixes. Anything not named is treated
as public.

## porte/pg

`New(db *sql.DB) *Store`, then `Users()`, `Identities()`, `Sessions()` and `LoginCodes()`.

They are four types rather than one because two interfaces spell the same method differently —
`SessionStore.Find` takes a token hash, `IdentityStore.Find` takes a provider and a subject — and
Go cannot carry both on one receiver. Renaming a method to dodge that would leak a storage
accident into the contract.

`Schema` is a constant. Apply it through the app's own migrations, never at boot: a schema
applied on startup races every other replica. `EnsureSchema(ctx, db)` exists for tests and local
development. It carries an idempotent `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` for
`porte_login_codes.consumed_at`, so a deployment that already applied an earlier `Schema`
migrates by re-applying it.

`UpsertFromOIDC` runs in one transaction. A login that created a user but failed to link the
identity would create a second user on the next attempt. The insert is
`ON CONFLICT (email) DO NOTHING RETURNING id` and re-selects when it returns nothing: the
existence check before it is a read in a `READ COMMITTED` transaction, so two first logins for
the same new user — a double click, two tabs, a retried callback — both pass it and both arrive
at the insert. Letting the loser adopt the winner's row turns a unique-violation 500 on the login
path into a second successful login.

`Consume` stamps `consumed_at` rather than deleting the row, and the stamp is what tells a replay
from a typo. Nothing usable survives it: what is kept is the SHA-256 of a credential that is
already spent, and `DeleteExpired` sweeps those rows on the same schedule as the ones nobody
exchanged, so both are gone within `LoginCodeTTL` of being issued.
