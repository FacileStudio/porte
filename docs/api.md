# porte — API

Every exported symbol, package by package. The reasoning for each decision is in
[SPEC.md](../SPEC.md) §5.

| Package | What it is | Depends on |
|---|---|---|
| `porte` | The frozen contract: types, interfaces, wire shapes. No behaviour | the standard library |
| `porte/session` | The credential: issuance, the cookie, the middleware, `POST /auth/logout` | `porte`, `tronc/errors`, `tronc/httpjson`, chi |
| `porte/oidc` | The engine: the flow, the six OIDC routes, the avatar guard | `porte`, `porte/session`, go-oidc, oauth2, tronc, chi |
| `porte/local` | Email and password: argon2id, register, login, set-password | `porte`, `porte/session`, `golang.org/x/crypto/argon2`, tronc, chi |
| `porte/pg` | The identity tables and the four stores over them | `database/sql` |
| `porte/avatarfs` | A filesystem `AvatarStore` and the handler that serves it | the standard library |

**The contract package depends on nothing outside the standard library, and that is a constraint
rather than a coincidence.** An app's stores and domain code compile against plain types and
never see `go-oidc`, `golang.org/x/oauth2` or a database driver. It is why `Claims` carries plain
fields and `TokenSet` exists instead of an `*oauth2.Token`, and it is why the engine is a
separate package rather than living here: only an app's `main.go` imports `porte/oidc`.

`porte/session` sits below both kits for the same reason one layer down. It carried the same
dependencies as the engine until v0.2, because it *was* the engine — and the price of that showed
up on the first adoption, where an app with a password form could not mint a session or set the
cookie. `porte/local` depends on the manager and not on `porte/oidc`: an app that wants only
passwords must not compile an OIDC client.

## Errors

| Symbol | What it is |
|---|---|
| `ErrNotFound` | A store found no row. Stores are implemented by consumers, so the contract needs its own sentinel rather than leaking `sql.ErrNoRows` or a GORM error across the boundary |
| `ErrCodeConsumed` | A login code was already exchanged. Separate from `ErrNotFound` because a replayed code is an attack and an unknown one is a typo |
| `ErrWrongPassword` | `invalid email or password`. Deliberately what an **unknown address** returns too |
| `ErrEmailTaken` | The address already carries a local identity |
| `ErrRegistrationClosed` | Registration is off and an account already exists |
| `ErrWeakPassword` | Shorter than `local.Config.MinPasswordLength` |
| `ErrInvalidEmail` | The address did not parse |

`ErrWrongPassword` covering an unknown address as well is the point, not an omission: an error
that distinguishes them turns the login form into an account enumeration oracle, and
`local.EqualizeTiming` closes the half of that oracle a message cannot.

**These five carry the frozen message text, not a wrappable error value.** `porte/local` returns
a `tronc` error — `errors.Unauthorized(porte.ErrWrongPassword.Error())` and so on — so the status
code arrives with it and `httpjson.WriteError` needs no glue, but `errors.Is` against the sentinel
does **not** match. Match on the constant's text if a handler has to branch. `ErrWeakPassword` is
declared and currently unused: the length failure carries the configured minimum in its message,
which the constant cannot.

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
| `RouteRegister` | `POST /auth/register` |
| `RouteLoginLocal` | `POST /auth/login` |

The first three are served at these exact paths with these exact response shapes by all six Go
apps today, which is what makes them safe to freeze. The last two are where every app in the
suite already serves its password login, for the same reason.

`RouteLogout` is mounted by `session.Manager`, not by either kit. Ending a session is not an OIDC
concern and never was — gating it behind a provider cost the first adopter a second logout handler
answering a second response shape.

`ProviderLocal` (`"local"`) is the `Provider` value a password identity is stored under, keyed on
the normalised email as its `Subject`. It keeps `(Provider, Subject)` the account matching key
whichever way the human signed in.

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
| `CredentialsRequest` | `/auth/register`, `/auth/login` | `email`, `name` (register only), `password` |
| `ExchangeRequest` | `/auth/oidc/exchange` | `code` |
| `ExchangeResponse` | `/auth/oidc/exchange`, `/auth/register`, `/auth/login` | `user_id`, `token` |
| `LogoutResponse` | `/auth/logout` | `logged_out` |
| `SyncProfileResponse` | `/auth/sync-profile` | `synced` |

`ExchangeResponse.UserID` is a **string** on the wire while `Identity.UserID` is an `int64` in
Go. That is deliberate: to a CLI the field is an opaque identifier, so changing its JSON type
breaks clients and buys nothing.

`SyncProfileResponse.Synced` is false when the call was a no-op because the rate limit had not
elapsed. It is not an error.

`ExchangeResponse` doing double duty for the local routes is deliberate: a register and a login
hand back the same pair a CLI exchange does, and the cookie is set alongside it, so one response
serves a browser and a terminal. `CredentialsRequest.Name` is ignored by the login. An app whose
frontend expects the `{token, user}` body every existing Facile app answers does not mount these
routes — it calls `local.Kit.Register` and `local.Kit.Login` from its own handlers, which is the
supported path and not a workaround. `porte` has no idea what a user looks like.

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
an OIDC subject and a local password are two rows, not two columns, which is what made v0.2 a
new package rather than a schema break. `PasswordHash` is empty on a federated row and carries a
PHC-encoded argon2id string on a local one; `Subject` is the normalised email there.

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

`Claims.EmailVerified` is true when the provider said so. A token with no `email_verified` claim
sets it false, because a provider that asserted nothing has not verified anything; an operator
who knows better sets `Config.TrustEmailWithoutVerifiedClaim`. An explicit `email_verified: false`
is a refusal and no configuration overrides it.

### PasswordUserStore

```go
CreateFromPassword(ctx context.Context, email, name string) (userID int64, err error)
FindByEmail(ctx context.Context, email string) (userID int64, err error)
```

The app's half of a local account, kept **separate from `UserStore`** because an app may enable
passwords, federation, or both, and neither should force the other's method into its store.
`porte/pg`'s `UserStore` implements both, so an app on the default tables passes the same value.

`porte` has validated the address, checked the length and hashed the password by the time
`CreateFromPassword` is called. `FindByEmail` returns `ErrNotFound` for an unknown address, and
that answer is what makes registering a password against an address that already signed in
through the IdP add an identity row rather than a second account.

As with `UpsertFromOIDC`, the side effects are the app's on purpose — the rule that the first
account created is an administrator is product behaviour. It is also why **`porte` cannot make
registration race-free by itself**: counting accounts and inserting one must happen under a lock
on a database `porte` does not own, so the lock stays where every Facile app already takes it.

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

## porte/session

The credential, on its own, below both kits. In v0.1 this code lived in `porte/oidc`, where
issuance, the cookie, the authenticator, the middleware and `POST /auth/logout` were all reachable
only through an OIDC kit. The first adoption priced that: an app with its own password form could
not mint a `porte` session or set `porte`'s cookie, so half its logins carried an `HttpOnly`
cookie and the other half a token in `localStorage` — the exact split the cookie was adopted to
end. Nothing about the behaviour changed in the move; three missing methods were added.

### Manager

`New(cfg porte.Config, deps Deps) (*Manager, error)`. Only `Deps.Sessions`, a
`porte.SessionStore`, is required. `Deps.Logger` defaults to `slog.Default()`, `Deps.Now` to
`time.Now` — it is there so a test can age a session past an idle window without sleeping for a
week — and `Deps.Claims` is a `ClaimsSource`, normally supplied later by `porte/oidc`.

**Build exactly one, and pass it to every kit.** Two managers over the same table would each keep
their own idea of the clock and the cookie, and only one of them would be right.

| Method | What it does |
|---|---|
| `Mount(chi.Router)` | Registers `POST /auth/logout`, behind `RequireAuth` |
| `Issue(ctx, userID, label) (token string, s porte.Session, err error)` | Mints a session, stores only its hash, returns the plaintext once. A `label` makes the row a named API token instead of a login |
| `IssueCookie(ctx, w, r, userID) (token string, s porte.Session, err error)` | `Issue` plus the `Set-Cookie`, and it still returns the token, so one endpoint serves a browser and a CLI |
| `Clear(ctx, w, r) error` | Ends the session **this request authenticated with** and expires the cookie |
| `RevokeUser(ctx, userID) (int64, error)` | Drops every session a user holds |
| `RequireAuth(http.Handler) http.Handler` | Rejects unauthenticated requests |
| `Optional(http.Handler) http.Handler` | Attaches an identity when there is one, lets the request through either way |
| `Authenticate(w, r) (porte.Identity, error)` | What both middlewares are, exported for a caller outside a chain — a WebSocket upgrade |
| `WithClaims(ClaimsSource) *Manager` | Attaches the claims source after construction |
| `Config() porte.Config` | The resolved configuration, mostly so a caller can read the TTLs it did not set |

`IssueCookie` is the method v0.1 was missing, and it is the one that makes adoption whole: without
it an app's own login could not put its session where `porte`'s middleware, its CSRF rule and its
idle window expect to find it.

`Clear` revokes by session id **and** by the id of the caller's own session, so a handler cannot
end somebody else's by guessing an integer. `RevokeUser` is what back-channel logout calls, and it
is the only mechanism by which an administrative deactivation in an identity provider reaches an
app that issued its own opaque session — see [SPEC.md](../SPEC.md) §13 for the deployment gap
that currently blocks it against the suite's Authentik.

`Authenticate` also writes: it deletes a session row it finds dead, and coalesces `last_used_at`
writes to one a minute. The column exists so a user can recognise a session in a list, and a
minute of resolution does that without an `UPDATE` on the hot path of every request.

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

The idle window applies to the cookie transport only. A bearer is a CLI or an API token, which is
idle by design and is the one class of credential with no human present to renew it.

### ClaimsSource

```go
type ClaimsSource interface {
	Attach(ctx context.Context, identity *porte.Identity)
}
```

The parts of an identity only a federated provider can answer for. `oidc.Kit` implements it and
`oidc.New` attaches itself through `WithClaims` when `ClaimsScope` is set. It is an interface
precisely so this package does not import `porte/oidc` — that would put `go-oidc` back into every
binary and undo the split. An app with only a local login leaves it nil and pays one query per
authenticated request, the session lookup, which is what it pays today.

### Cookies

| Method | What it does |
|---|---|
| `SetSessionCookie(w, r, token)` | The session cookie, `MaxAge = SessionTTL` |
| `ReadCookie(r, base) (string, bool)` | Reads a cookie by **base** name, resolving the `__Host-` prefix |
| `SetCookie(w, r, base, value, maxAge)` | `Path=/`, `HttpOnly`, `SameSite=Lax`, `Secure` derived |
| `ClearCookie(w, r, base)` | Expires **both** spellings |

They take a base name and are exported because `porte/oidc` writes the short-lived `oidc_state`
flow cookie through them, and an adopting app may have a cookie of its own that has to agree about
the prefix and the `Secure` verdict. `ClearCookie` expiring both spellings is not tidiness:
clearing only the prefixed one would leave a legacy cookie behind on exactly the logout that is
meant to migrate the user off it.

The prefix, the `Secure` derivation and the legacy-cookie migration are documented in
[configuration.md](configuration.md).

## porte/oidc

### Kit

`New(ctx, cfg, Deps) (*Kit, error)` performs discovery and returns the engine. A disabled config
is not an error — it returns a kit that serves `RouteConfig` and nothing else, which is what an
app running without SSO needs.

`New` is the boot path, so every detectable misconfiguration is detected there: a half-filled
environment, an unreachable issuer, a missing store, a roles scope the provider does not
advertise, and a session manager built from a different configuration.

| Method | What it does |
|---|---|
| `Mount(chi.Router)` | Registers the routes at the frozen paths, relative to that router |
| `Sessions() *session.Manager` | The manager this kit issues through |
| `RequireAuth(http.Handler) http.Handler` | The manager's middleware, re-exported so wiring reads as it did in v0.1 |
| `Optional(http.Handler) http.Handler` | Likewise |
| `Attach(ctx, *porte.Identity)` | The `session.ClaimsSource` implementation. The manager calls it; an app does not |
| `Config() porte.Config` | The resolved configuration |
| `Enabled() bool` | Whether the OIDC routes are live |

`Deps` carries `Users`, `Identities`, `Codes`, an optional `Avatars`, an optional `Logger`, an
optional `ConfigExtra` — and `Sessions`, which is now a **`*session.Manager`** rather than a
`porte.SessionStore`. That is v0.2's breaking change. The manager is passed in rather than built
here because an app with a local login shares one between `porte/oidc` and `porte/local`.
`Sessions` is required whether or not OIDC is enabled; `Users`, `Identities` and `Codes` become
required once it is.

**`New` refuses a kit and a manager built from different configurations**, naming the field:
`OIDC_REDIRECT_URL`, `OIDC_SUCCESS_URL`, `SessionTTL` or the resolved `SessionIdleTTL`. They share
one `Config` type but are constructed separately, and a manager built with a different redirect or
success URL reaches a different `Config.HTTPS()` verdict — which silently changes whether the
session cookie is `Secure` and carries the `__Host-` prefix. A security property decided by a
typo, with nothing failing until an attacker notices, is cheaper to refuse at boot.

`Mount` registers `GET /auth/config` always; the OIDC routes and `POST /auth/sync-profile` appear
only when a provider is configured. **`POST /auth/logout` is not among them** — it belongs to the
session manager since v0.2, so `sessions.Mount(router)` is a separate line and not an optional
one.

`Deps.ConfigExtra func() map[string]any` adds fields to `GET /auth/config`. Every app in the
suite serves a superset there — `allow_registration` in Journal, a legacy `password_auth` in
Mycelium — and `porte` owns the path, so without this the app either drops its key or registers
the route twice and chi panics. `sso_only` and `oidc_enabled` are written over whatever the map
contains: the frontend decides on those two whether to draw a password form at all, and they
answer to the configuration alone.

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

## porte/local

Email and password, argon2id, landing in the same session as a federated login. Five of the six
apps `porte` replaces have a password form, so the alternative to this package was six of them.

What is shared is not the flow, which is easy, but its details — the constant-time compare, the
equalised timing on an unknown address, the length floor, the refusal to say which half of the
pair was wrong. Those are what drift across six copies, and what an app gets wrong quietly.

### Kit

`New(cfg Config, deps Deps) (*Kit, error)`. It fails rather than degrading: a half-wired local
login that answers 500 on the first sign-up is worse than one that refuses to boot.

| Method | What it does |
|---|---|
| `Mount(chi.Router)` | `POST /auth/login`, plus `POST /auth/register` when `AllowRegistration` |
| `Register(ctx, w, r, email, name, password) (userID int64, token string, err error)` | Creates the account, sets the cookie, returns the bearer token |
| `Login(ctx, w, r, email, password) (userID int64, token string, err error)` | Verifies and issues |
| `SetPassword(ctx, userID, email, password) error` | Adds or replaces a password on an existing account |

**`Register` and `Login` are exported as a service, not only as routes**, and that is the
supported path for every app that already answers `{token, user}` from its login. `porte` has no
idea what a user looks like, so the app keeps its response shape and `porte` keeps the credential.
`Mount` exists for the app that has no opinion; it answers `ExchangeResponse` with
`Cache-Control: no-store`, 201 on a register and 200 on a login.

`SetPassword` is what an account settings screen calls, and what an app calls to give a
federated-only user a password.

The email is lowercased, trimmed and parsed before anything else, and the normalised form is the
identity's `Subject` — so two spellings of one address cannot become two accounts.

**A human may hold a password identity and a federated one at once, and they are one account.**
`Register` against an address that already signed in through the IdP looks the user up by email,
finds no local identity, and adds one. It does not create a second user and does not disturb the
OIDC subject. That is what giving identities their own table in v0.1 was for. A second local
registration for the same address is `ErrEmailTaken`.

`Login` answers `ErrWrongPassword` for an unknown address, a malformed address and a wrong
password alike, and runs `EqualizeTiming` on the first two. An error that distinguishes them is an
enumeration oracle; so is answering in a millisecond where the real path takes sixty.

### Config

| Field | Default | What it does |
|---|---|---|
| `AllowRegistration` | `false` | Whether `POST /auth/register` is mounted at all, and whether registration is open past the first account |
| `MinPasswordLength` | `12` | A length floor and nothing else |

`DefaultMinPasswordLength` is 12. No character classes: they push users towards `P@ssw0rd1` and
buy nothing a length does not.

`AllowRegistration` is two rules wearing one name, and the difference matters when calling
`Register` directly. `Mount` does not register the route when it is false. `Register` itself, when
it is false, allows the **first** account and refuses the rest with `ErrRegistrationClosed` —
locking an empty instance out of itself is not a security property, and every app in the suite
already carries that exception.

There is no `SSOOnly` here. `porte.Config.SSOOnly` suppressing the password routes is the app
declining to mount this kit, not this kit declining to serve.

### Deps

`Users` (`porte.PasswordUserStore`), `Identities` (`porte.IdentityStore`), `Sessions`
(`*session.Manager`) and `Count` are all required; `Logger` defaults to `slog.Default()`.

`Count func(ctx) (int64, error)` reports how many accounts exist, for the first-account exception.
It is the app's because only the app knows what a user row is — and because **`porte` cannot make
registration race-free by itself**: counting and inserting must happen under a lock on a database
`porte` does not own. Every Facile app already takes that advisory lock.

### Hashing

| Symbol | What it does |
|---|---|
| `HashPassword(password) (string, error)` | PHC-encoded argon2id |
| `VerifyPassword(password, encoded) bool` | Constant-time compare. A malformed or empty encoding is false for every input |
| `EqualizeTiming(password)` | One verification against a fixed throwaway hash |

**The parameters — 64 MiB, three passes, two lanes, 16-byte salt, 32-byte key — are copied from
the apps rather than chosen.** Every password hash already in a Facile database keeps verifying,
which is what makes adopting this a code change and not a password reset. The PHC encoding carries
them, so raising the cost later verifies old hashes at their own settings instead of locking
everyone out.

`VerifyPassword` returning false for an empty encoding is what makes an account created through
SSO — which has no password hash — impossible to sign into with one.

`EqualizeTiming` is exported because an app calling `Login` from its own handler may have a branch
of its own that returns before `porte` is reached. Without it a login form answers "no such
account" in a millisecond and "wrong password" in sixty, which is the same oracle as different
error messages, only harder to notice in review.

## porte/pg

`New(db *sql.DB) *Store`, then `Users()`, `Identities()`, `Sessions()` and `LoginCodes()`.

`Users()` implements `porte.UserStore` **and** `porte.PasswordUserStore`, so an app on the default
tables passes the same value to `oidc.Deps.Users` and `local.Deps.Users`. An app with its own
`users` table implements whichever halves it needs; Journal implements both over its own.

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

## porte/avatarfs

`New(dir, urlPrefix string) (*Store, error)`. `Store` implements `porte.AvatarStore` and is the
filesystem half of the avatar story: `porte/oidc` fetches the bytes behind the SSRF guard, this
writes them somewhere a browser can ask for them. Five apps carry their own copy of it, and the
differences between the copies — a different extension table, a different permission bit, a write
that is not atomic — are accidental rather than deliberate.

`New` creates `dir` when it is missing, `0755`, and refuses an empty prefix. The prefix is
normalised to a leading slash and no trailing one, so `/avatars`, `avatars` and `/avatars/` are
the same store. It is a path and not a full URL: the returned avatar URLs are site-relative,
which is what keeps the store from having to know the public hostname it is behind.

| Method | What it does |
|---|---|
| `Put(ctx, key, data, contentType) (avatarURL string, err error)` | Writes `<key>.<ext>` and returns `<prefix>/<key>.<ext>` |
| `Remove(ctx, avatarURL) error` | Deletes the file that URL names, or does nothing when it is already gone |
| `Handler() http.Handler` | Serves the stored avatars, prefix-stripping included |
| `URLPrefix() string` | The normalised prefix, which is what to mount `Handler` at |

The extension comes from the **validated** content type — `image/png` → `png`, `image/jpeg` →
`jpg`, `image/gif` → `gif`, `image/webp` → `webp` — and an unknown type is an error rather than a
default. Guessing `.png` for something that is not a PNG produces a file every browser refuses
and no log line explains. Content-type parameters are dropped, so a caller passing a
`Content-Type` header through verbatim is not punished for it.

`Put` writes a temp file in the same directory and renames it into place, mode `0644`. The
directory is also the directory being served, so a plain create-then-write is readable while it
is still half a PNG, and the reader that catches it is a user looking at their own broken profile
picture. Writing the same key again replaces the file, which is the point of a stable key: a
re-sync overwrites instead of accumulating one file per login.

**The key must be a plain `[A-Za-z0-9_-]` token, at most 128 characters, and never empty.** It is
`Claims.AvatarKey()` today — a hex hash, which passes trivially — so the rule is not for that
caller. It is for the second one: a store that joins a caller-supplied string onto a filesystem
path is a directory traversal waiting for somebody to pass it an email address, a subject from an
ID token, or a filename.

`Remove` accepts what `Put` returned and also an absolute URL whose path carries the prefix,
since an app fronted by a CDN may have recorded the absolute form. Anything else is refused: a
URL without the prefix belongs to another store, and one that walks out of the directory belongs
to nobody. It is a no-op when the file is already gone, because a profile cleared twice is not an
error.

`Handler` strips the prefix itself, so it is mounted whole —
`router.Handle(store.URLPrefix()+"/*", store.Handler())` — rather than depending on the caller
spelling a `StripPrefix` correctly for the store to be safe. It serves `GET` and `HEAD` only, and
nothing but names `Put` could have written: no directory listing, no separator in the path, no
extension outside the table. That is stricter than `http.FileServer`, and it is what makes
serving a directory that also holds temp files acceptable.

Responses carry `Cache-Control: public, max-age=300`. Not `immutable`, and not a year: the URL is
stable per identity, so the same URL serves different bytes after a profile re-sync, and a long
max-age would leave the old face on screen until someone cleared their browser cache by hand.
Five minutes is the suite's profile sync interval, so a stale avatar outlives its replacement by
at most one interval while still being served from cache on every page of a session.
