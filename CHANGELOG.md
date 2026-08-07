# Changelog

Decisions are recorded with their reasoning. The reasoning is the part that stops a future
session from undoing a deliberate choice.

## Unreleased

### The engine and the stores

`porte/oidc` and `porte/pg`: the flow, the seven routes, the middleware, the SSRF-guarded avatar
fetch, and the four tables. Tested against a real PostgreSQL, not a fake — every interesting
behaviour in `pg` is PostgreSQL's own.

- **`porte/oidc` is a separate package, not the root.** SPEC §8 put the implementation in the
  root package, which contradicts the zero-dependency decision taken with the contract: an app's
  `UserStore` must not compile against `go-oidc`. The literal promise is unreachable inside one
  module anyway — `go.mod` requirements are module-scoped — but the layering is worth keeping,
  and it costs one import line in `main.go`. Only that file sees the engine.
- **Four store types in `porte/pg`, not one.** `SessionStore.Find` takes a token hash and
  `IdentityStore.Find` takes a provider and a subject; Go cannot carry both on one receiver.
  Renaming a method to dodge that would leak a storage accident into the contract.
- **The Go floor is 1.25, not 1.24.** SPEC §8 left this open and leaned 1.24 on the principle
  that a library floors low. `go-oidc` v3.20 requires 1.25, so the dependency decided. It costs
  nothing: the apps are on 1.25 and `tronc/migrate` already declares 1.25.7.
- **The avatar SSRF guard now runs inside the dialer.** All six existing copies resolve the
  hostname, check the addresses, then call `http.Get` — which resolves again. A DNS record that
  answers publicly on the first lookup and privately on the second walks straight through.
  Checking at connect time closes that window and covers redirects for free.
- **`UpsertFromOIDC` refuses an unverified email that already belongs to someone**, with a
  message, instead of hitting the unique index and returning a 500 from the login path.
- **The startup guard is split in two**, because only half of it is checkable at boot: `New`
  verifies the roles scope against the discovery document, and the callback fails loudly when
  the scope was granted but no claim arrived. Between them there is no path where a
  half-configured provider denies everyone in silence.

### Contract corrections, found by implementing it

SPEC §11 froze the contract and asked for a review before anything was built on it. Writing the
implementation *was* the review, and it found three things wrong:

- **`LoginCode.SessionID` is gone.** The session is created at exchange time, not at callback
  time. The old shape could not work: the session row stores only a hash, so handing the CLI a
  usable token later would have meant keeping the plaintext at rest. The stated reason for
  creating it up front — avoiding a second write path that could half-succeed — does not survive
  contact with the fact that creating a session is one insert. `Consume` is atomic, so a code
  still yields at most one session.
- **`AvatarStore.Put` takes an opaque key, not a user id**, and `Claims` gained `AvatarURL` and
  `AvatarKey()`. The old signature had an ordering problem with no solution: the avatar URL must
  reach the app's user row, the app writes that row in `UpsertFromOIDC`, and `Put` needed a user
  id that does not exist until that call returns. Keying on the identity instead lets the fetch
  run first and the URL ride into the upsert. A stable key also means a re-sync overwrites rather
  than accumulating one file per login.
- **`Config.Validate` requires an absolute http(s) issuer.** The old check called `url.Parse` and
  tested the error, which catches almost nothing: `sso.facile.studio` parses fine as a relative
  path, and the failure surfaces later as an opaque discovery error naming neither the variable
  nor the problem.

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
