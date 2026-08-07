# porte — API

Every exported symbol. This is the frozen contract: types, interfaces and wire shapes, with no
behaviour behind them yet. The reasoning for each decision is in [SPEC.md](../SPEC.md) §5.

**The package depends on nothing outside the standard library, and that is a constraint rather
than a coincidence.** An app implementing `UserStore` must not inherit `go-oidc`,
`golang.org/x/oauth2` or a database driver from `porte`. It is why `Claims` carries plain fields
and `TokenSet` exists instead of an `*oauth2.Token`. The implementation may depend on whatever
it needs; the boundary an app sees may not.

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

`Find(ctx, provider, subject)`, `Save(ctx, identity)`, `ListByUser(ctx, userID)`.

`Find` returns `ErrNotFound`. `Save` inserts or updates by `(Provider, Subject)`. `ListByUser`
returns every way a human can authenticate, which is what an account settings screen needs.

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

`Consume` returns the code and deletes it in one operation, so a replay finds nothing. It
returns `ErrCodeConsumed` when the row is gone but the code was well-formed, and `ErrNotFound`
otherwise.

### AvatarStore

`Put(ctx, userID, data, contentType) (avatarURL string, err error)` and `Remove(ctx, avatarURL)`.

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
of them can offer "your active sessions".

| Method | What it does |
|---|---|
| `Expired(now) bool` | A zero `ExpiresAt` never expires — that is what a long-lived API token wants |
| `IsAPIToken() bool` | Whether the row was created as a named token rather than an interactive login |

`LoginCode` carries `CodeHash`, `UserID`, `SessionID`, `ExpiresAt`, and `Expired(now) bool`. The
session row is created up front, so the exchange is a lookup rather than a second write path
that could half-succeed.
