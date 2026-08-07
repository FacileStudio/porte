# Changelog

Decisions are recorded with their reasoning. The reasoning is the part that stops a future
session from undoing a deliberate choice.

## Unreleased

### The frozen contract, as Go types

`porte.go`, `identity.go` and `session.go`: types, interfaces and wire shapes only, no
behaviour. This is SPEC.md §11's first step, taken after diffing the six `modules/auth/`
implementations rather than before.

- **Zero dependencies, standard library only.** An app implementing `UserStore` must not
  inherit `go-oidc`, `golang.org/x/oauth2` or a database driver from `porte`. That is why
  `Claims` carries plain fields and `TokenSet` exists instead of an `*oauth2.Token`. The
  implementation may depend on whatever it needs; the boundary an app sees may not.
- **`Identity.UserID` is an `int64`.** Every app passes a decimal string around today. The
  conversion moves to the edge, and the type matches `porte_users.id` and the `int64` foreign
  keys already in place. `ExchangeResponse.UserID` stays a string on the wire: to a CLI it is
  an opaque identifier, so breaking it buys nothing.
- **The middleware yields a typed `Identity`.** It replaces
  `Authenticate(ctx, string) (string, any, error)` followed by an
  `interface{ GetEmail() string }` assertion, which is a runtime failure mode sitting in the
  auth path of six apps.
- **Stores take hashes, never tokens.** Keeping the plaintext out of the store interface is
  what stops it reaching a log line or a query parameter.
- **`SessionStore.Find` does not filter on expiry.** An expired session and a missing one are
  different answers, and only the caller knows which error to return.
- **`ErrCodeConsumed` is separate from `ErrNotFound`.** A replayed login code is an attack;
  an unknown one is a typo. One error value buys that distinction in the logs.
- **`CSRFHeaderName` is `X-Facile-CSRF`, any non-empty value** (SPEC §7 Q5). No app sends a
  CSRF header today, so the name was free. Presence is the whole signal — a browser will not
  attach a custom header cross-site without a preflight — so there is no token to mint,
  distribute or rotate.
- **`DefaultClaimsTTL` is five minutes** (SPEC §7 Q6), deliberately the same number as the
  existing `profile_synced_at` rate limit. One refresh cadence, not two.
- **`SessionCookieName` is `session`,** taken from Courrier and Agenda, which already ship the
  cookie transport. Adopting their name means those two do not have to log everyone out twice.

### SPEC.md corrected against source

The diff found three claims that had gone stale, all dated in place rather than deleted:

- **Matching on `sub` is already fixed in all six apps** — it is the HEAD commit of every
  `modules/auth/`, and every `schemas/user.go` now carries `OIDCSubject *string uniqueIndex`.
  It was listed as "the most severe item"; `porte` now preserves it instead of introducing it.
- **The cookie transport is already live in Courrier and Agenda**, including a `Secure` flag
  derived from `X-Forwarded-Proto`, which is the correct test behind Traefik.
- **Constant-time state comparison already exists in Plume.** PKCE and the nonce are still
  missing everywhere, as specified.

New findings recorded: Courrier and Agenda encrypt OIDC tokens at rest while four apps do not;
Courrier's middleware still accepts `?token=` and Vision's `?api_key=`, which `porte` will not
carry forward; `authcrypto` has three distinct hashes across seven apps, not one.

### Repo

- `.github/workflows/ci.yml`, copied from `caisse` and pinned to Go 1.24 — the floor `go.mod`
  documents. Held back until the first package existed, because `go vet ./...` on an empty
  module exits non-zero. The PostgreSQL service is present from the start: a database test that
  skips itself when the URL is unset passes silently, and a green CI that ran nothing is worse
  than a red one.
