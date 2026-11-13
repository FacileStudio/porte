# Contract changes from v0.11.0 to v0.20.0

Source: `CHANGELOG.md` at v0.18.0. One line per change a port must match. Read the changelog entry for the reasoning.

## v0.12.0 (`directory` v0.3.0)

- `directory.Deletions` polls `GET /api/directory/deletions`, pages through it in one `Poll`, and calls `OnPersonDeleted(ctx, provider, subject)` once per person.
- Deletions persist a cursor plus every handled subject through an app-implemented `StateStore` (load and save one blob).
- A failing callback or erase leaves that person pending, keeps the cursor before the earliest failure, and returns the errors joined.
- `Deletions.Handler()` accepts only a `secevent+jwt`, RS256, right `iss` and `aud`, short time window, `user-deleted` event; anything else is 400.
- The push handler answers 503 on a key-fetch failure or an unknown `kid` inside the one-minute refetch gap.
- Discovery for the push must name the configured issuer; `jwks_uri` must be https unless the issuer is plain http; key fetches follow no redirects.
- The callback runs before `Erase`, so the app can still resolve its account from porte's identity rows.
- `pg.Store.EraseIdentity` deletes one identity with its tokens, sessions, named tokens, login codes and magic links, and leaves `porte_users` alone.
- `directory.Client` gains `Deletions(ctx, since)`; `directory` stays standard library only.

## v0.12.1

- `EraseIdentity` and the unverified-address purge skip optional tables (`porte_magic_links`, `porte_login_codes`) that the schema lacks, resolved once per store with `to_regclass`.
- `porte_identities` and `porte_sessions` stay required: erasing errors when either is missing.

## v0.13.0

- `pg.New` takes options; `pg.WithTokenSealer(sealer)` seals `porte_identities.access_token` and `refresh_token`.
- Sealing is AES-256-GCM, random 12-byte nonce per value, key from HKDF-SHA256 over a 32-byte secret, stored as `pv1:` + base64url(nonce || ciphertext || tag). Pinned in `vectors/sealer.json`.
- Reads open `pv1:` values and return anything else as plaintext; writes always seal when a sealer is configured.
- A sealed value no key opens (wrong key, tampered, no sealer) reads as an empty token: fail closed, no panic, no log.
- `NewTokenSealer(newest, older...)` seals with the first secret and opens with all of them.
- An empty token stays empty; it is never sealed.
- `IdentityStore.ResealIdentities(ctx)` (optional) seals remaining plaintext rows in batches, is idempotent, never blanks a row, and loses to a concurrent `Save`.
- `ParseTokenSealer(spec)`: empty spec is a nil sealer (sealing off); otherwise comma-separated secrets, newest first, each 32 bytes as hex or standard base64.

## v0.14.0 (`mcpauth` v0.1.0, new nested module)

- `jwt.Claims` gains `Audience`, `ClientID` (`client_id`), `ID` (`jti`) and `ExpiresAt`.
- `jwt.Config.ExtraAudiences` accepts further audiences through the same discovery and key cache.
- `oidc.ResolveBearer` is exported: the `(iss, sub)` to account mapping of the Authorization header path.
- `mcpauth.Verifier` verifies RS256 offline, requires `aud` to name `Config.Resource` byte for byte, and resolves through `oidc.ResolveBearer` (no email fallback).
- `mcpauth` `Config.Audience` accepts the app's client id only on delegated tokens (`act` present).
- Every rejected MCP token is `auth.ErrInvalidToken` with the text `invalid token`; an unreachable JWKS or identity store is a 500.
- `mcpauth.Require` adds `error="insufficient_scope"` on a 403 and `error="invalid_token"` on a 401 that carried a token.
- A zero `ClockSkew` becomes 30 s, matching the jwt leeway.
- `ScopesFor(prefix)` names `<prefix>.read` and `<prefix>.write`; a write grant implies read.
- `ProtectedResourceMetadata(resource, issuer, scopes)` builds the RFC 9728 document; `MetadataURL(resource)` gives its well-known URL.
- `ThirdParty(info)` is false only for a token Bulle exchanged (`act` present and `client_id` = `bulle`).
- `CheckPlan` and `PlanGate` read `ai.access` from a `forfait.Store` under the token's subject and answer 402 `payment_required` with `upgrade_url` = Registre `/spaces`; a nil store refuses every third-party token.

## v0.15.0

- New package `porte/exchange`: `exchange.New(Config{Issuer, ClientID, ClientSecret, Identities})`.
- `Token(ctx, userID, Target{Audience, Scopes})` reuses the stored Registre access token while valid, else refreshes, then exchanges it (RFC 8693); results are cached until expiry minus `Margin` (30 s).
- Refreshes are serialized per user across every audience; waiting honours the caller's context.
- The refresh and its save run on a context the caller cannot cancel; a failed save keeps the new refresh token in memory for the next refresh.
- On `invalid_grant`, if the stored refresh token changed since it was read, the exchanger retries once with the new one.
- `ErrReconnect` (tronc `failed_precondition`) only for: no Registre identity, no refresh token, or Registre refusing the grant.
- Other refusals are `*RefusedError{Status, Code}`; a network error, timeout or 5xx wraps `ErrUnavailable`.
- `Do(ctx, userID, target, call)` retries the downstream call once with a fresh token on a 401; `Forget` and `ForgetUser` drop cached tokens.
- `Source(target)` binds a target to the request's user as `func(ctx) (string, error)`.

## v0.15.1

- `exchange` picks the identity that holds a refresh token, most recently synced first, instead of the first match.

## v0.16.0 (`mcpauth` v0.2.0)

- `(*oidc.Kit).ProvisionBearer(ctx, jwt.Claims)` creates the local account for a verified bearer subject through the login callback's own `persist` path.
- Provisioning refuses a token without an email, with `email_verified: false`, or with no `email_verified` unless `TrustEmailWithoutVerifiedClaim`; with a roles scope configured it needs roles.
- Every provisioning refusal and every caller-class store error wraps `oidc.ErrProvisionRefused`; a failed store does not.
- Concurrent first calls for one subject share one provisioning per process (`singleflight`); an existing account is returned untouched.
- `mcpauth.Config{Provision: true, Accounts: kit}` turns it on; `Verifier` refuses `Provision` without `Accounts`, or an `Accounts` kit with another issuer.
- `jwt.Claims.Profile` carries `email_verified` (nil when absent), `preferred_username`, `picture` and `locale`; an odd type drops the claim, not the token. Pinned in `vectors/jwt.json`.

## v0.17.0

- New opt-in package `kit`: `kit.Store` (a `porte.UserStore` over an app's own `users` table, configured by `kit.Columns`), `kit.RequireAuth`, `kit.Identity`, `kit.FromContext`, `(*kit.Store).EraseAccount`, `kit.PictureURL`, `(*kit.Store).BackfillPictures` and `kit.Mount`.
- `kit.Store` rewrites the stored email at sign-in only when the provider marks it verified; there is no option to change this.
- `kit.Mount` adds no route: it delegates to `session.Manager.Mount` and `oidc.Kit.Mount`, so every existing vector holds through it. No vector pins `kit` itself.

## v0.18.0 (`directory` v0.4.0)

- `kit.MountInvitations` registers `GET /me/invitations`, answering `{"count": n, "href": url}`: the invitation's page when n is 1, else `{issuer}/spaces`. Every failure answers 200 `{"count":0}`. Answers are cached per user for 60 seconds and concurrent requests for one user share one Registre call. Not part of `kit.Mount`.
- `directory.Client.Invitations(ctx, subject)` calls `GET /api/directory/invitations` with the client's Basic auth. A count that disagrees with the list, trailing data, an invitation without an id or with a link off the issuer's origin, or a body over `MaxInvitationsBytes` (64 KiB) is `ErrUnavailable`. One call is bounded by `InvitationsTimeout` (2 seconds). An empty subject is `ErrNoSubject` and sends nothing.
- No vector pins `kit.MountInvitations` or `Client.Invitations`; `directory_snapshot.json` is unchanged by v0.4.0.

## Where the Go source differs from the porte-rs plan

- `GET /auth/oidc?flow=mobile` with no mobile redirect configured answers 302 to the failure URL, not 400 (`vectors/routes.json`).
- The `__Host-` prefix is not an option: porte writes it whenever the cookie is Secure, and Secure is `RedirectURL`/`SuccessURL` https, TLS, or `X-Forwarded-Proto: https` (case-insensitive) (`vectors/cookie.json`).
- `directory` decodes with `encoding/json`: field names match case-insensitively, a duplicate key keeps the last value, and every field may be missing (`spaces`, `members` and all member strings included). Any decode error wraps `ErrUnavailable` (`vectors/directory_snapshot.json`).
- Go `Identity` is `UserID, Subject, Email, EmailVerified, Name, Roles, Scopes, Actor, SessionID, BrowserSession (v0.20.0), RolesSyncedAt`: it has no `Provider`, and the plan's struct lacks `EmailVerified`, `SessionID` and `RolesSyncedAt`.

## v0.18.1 to v0.18.3

No contract change for a port. All three releases touch only `kit`, the Go helper over an app's own users table: provider lookups match `<issuer>` and `<issuer>/` (v0.18.1), `kit.NewStore` writes `created_at` and `updated_at` where the table has no default (v0.18.2), and a `kit.Store` literal warns once (v0.18.3). `oidc`, `session`, `pg` and every vector are unchanged.

## v0.20.0 (`mcpauth` v0.3.0, `forfait` v0.1.3)

- Back-channel logout answers 503 `{"error":{"code":"unavailable","message":"could not fetch the provider keys"}}` when the JWKS cannot be fetched (unreachable, non-200, unreadable); every other verification failure stays 401 `invalid logout token` (`vectors/backchannel_logout.json`, input field `keys`).
- `Identity.BrowserSession` is true only for the session cookie on a row with no label; a bearer, a named API token sent as a cookie and a bearer JWT are false.
- `mcpauth.RequireOwnSession(r)`: no identity is 401 `missing auth`; anything but a browser session (no `Authorization` header, no `porte/keys` key, no actor, subject or scopes, a session id and a user id) is one 403 `permission_denied` "only the person's own session can confirm actions".
- `mcpauth.AccountExists(ctx, info, lookup)` answers `ErrNoAccount` for a token not from `Verifier` or a failed lookup.
- New vectors: `exchange_errors.json`, `mcpauth_tokens.json`, `provision_bearer.json`, `directory_erased.json`. Every vector's `source` names its release tag.
- `forfait.LimitError` gains `PlanLimit() (key, upgradeURL string)`.
