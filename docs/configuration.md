# porte — Configuration

Every environment variable and `Config` field the contract defines, and the traps behind them.

The variable names are the existing suite convention, unchanged: ten backends already read them,
so `porte` adopts the names rather than improving them.

## Environment

| Variable | Required | Default | What it does |
|---|---|---|---|
| `OIDC_ISSUER` | no | — | Issuer URL. **Its presence is what enables OIDC** |
| `OIDC_CLIENT_ID` | with issuer | — | Client ID of the provider application |
| `OIDC_CLIENT_SECRET` | with issuer | — | Client secret |
| `OIDC_REDIRECT_URL` | with issuer | — | Must match the redirect URI registered on the provider |
| `OIDC_SUCCESS_URL` | with issuer | — | Where the browser lands after a successful callback |
| `OIDC_CLAIMS_SCOPE` | no | — | The scope carrying the `roles` claim. **Its presence is what enables claims handling** |
| `SSO_ONLY` | no | `false` | Suppresses the local password routes entirely |

`porte` does not read the environment itself. An app builds a `Config` however it already builds
one — `troncenv` in every suite app today — and passes it in. A library that reads `os.Getenv`
behind your back is a library you cannot test twice in one process.

### The presence-enables-it convention

There is no `OIDC_ENABLED`. Setting `OIDC_ISSUER` is what turns OIDC on, and every app already
works this way (`oidcEnabled := appEnv.OIDC != nil`). A separate boolean would let a deployment
set the issuer and still be off, which is a support ticket waiting to happen.

The trap it creates is the half-configured provider: an issuer with no client secret. That is
what `Config.Validate` exists for — it names **every** missing variable at once, so a
misconfigured deployment takes one fix rather than four boots.

`Validate` also requires the issuer to be an **absolute http(s) URL**. `url.Parse` accepts almost
any string, so parsing it proves nothing: `sso.facile.studio` parses happily as a relative path
and then fails discovery at boot with an error that names neither the variable nor the problem.

### `SSO_ONLY` does not reject, it does not register

When `SSO_ONLY` is true the local password routes are never mounted. They do not return 403 —
they are not there. There is no endpoint to probe and no handler to reach by mistake.

**That is the app's line to write, not `porte/local`'s.** The kit has no `SSOOnly` field: it is
constructed and then not mounted, or not constructed at all. Putting the flag inside it would mean
a kit that answers 403 from a route it registered, which is precisely the thing this convention
avoids. `sso_only` still rides out on `GET /auth/config`, which is how the frontend knows not to
draw the password form in the first place.

## Config

| Field | Default | What it does |
|---|---|---|
| `Issuer` | — | Empty disables OIDC entirely. `Enabled()` reports it |
| `ClientID` | — | Required once `Issuer` is set |
| `ClientSecret` | — | Required once `Issuer` is set |
| `RedirectURL` | — | Required once `Issuer` is set |
| `SuccessURL` | — | Required once `Issuer` is set |
| `SSOOnly` | `false` | Local password routes are not registered |
| `TrustEmailWithoutVerifiedClaim` | `false` | Lets a token carrying **no** `email_verified` claim match an existing account by address. Never applies to an explicit `false` |
| `ClaimsScope` | — | Scope carrying the `roles` claim. Empty disables claims handling |
| `SessionTTL` | `30 days` | Browser session lifetime |
| `SessionIdleTTL` | `7 days` | How long a browser session may go unused before it stops authenticating |
| `ClaimsTTL` | `5 minutes` | How long a cached role claim is trusted |
| `LoginCodeTTL` | `60 seconds` | Window for a CLI to exchange its one-time code |
| `AcceptLegacyCookie` | `false` | Also read the session cookie under its unprefixed name over https, for one migration |

`Config.Resolved()` returns a copy with zero durations replaced by their defaults, so the rest
of the implementation never repeats the fallback. Call it once at construction. `SessionIdleTTL`
is not among them, because zero and negative mean different things there — `Config.IdleTimeout()`
resolves it instead.

| Method | Returns |
|---|---|
| `HTTPS() bool` | Whether the app is served over TLS, according to `RedirectURL` or `SuccessURL` rather than a proxy header |
| `IdleTimeout() time.Duration` | The idle window, or zero when it is disabled |

### The idle window

`SessionIdleTTL` is the one default `porte` does not inherit from the apps, because none of them
has an idle window at all. A session nobody has used for a week stops authenticating and its row
is deleted on the request that finds it, inside the thirty-day absolute lifetime. Active users
never meet it: `LastUsedAt` is refreshed on every request, coalesced to a minute of resolution,
which is far finer than a window measured in days.

Zero selects the seven-day default. A **negative** value disables the window and restores the
behaviour the apps have today, which is an absolute expiry and nothing else. That is the escape
hatch, and it is spelled negative rather than zero so that turning the protection off is
something a deployment says on purpose.

The window applies to the **cookie transport only**. Everything arriving as a bearer is a CLI or
an API token, and those are idle by design: a deploy script nobody runs for a fortnight, a
nightly job. They are also the one class of credential with no human present to renew it, so
expiring them would break exactly the callers who cannot recover. The risk the window addresses
is the browser left signed in on a machine somebody else can reach, which is a cookie.

A thirty-day credential that nothing can age out is the difference between a borrowed laptop
being a bad afternoon and a bad month.

### The defaults are measurements, not taste

Each number is what the apps already do, not a preference:

- **30 days** is the session lifetime every app hardcodes today.
- **60 seconds** is the existing CLI login code window.
- **5 minutes** is the existing `profile_synced_at` rate limit, reused for claims on purpose.
  One refresh cadence is easier to reason about than two, and it means a role revoked in the IdP
  stops mattering within five minutes while the IdP sees at most one refresh per user per five
  minutes rather than one per request.

**7 days** is the exception, and the only number here that was chosen rather than measured. No
app has an idle window today, so there was nothing to inherit — see above for why one exists.

### `OIDC_CLAIMS_SCOPE` — roles, and the two ways they go wrong

Claims are **off** unless `ClaimsScope` is set, and no app sets it today, so leaving it unset
regresses nothing. Setting it does three things: the scope is appended to the four `porte` always
requests, `porte` reads a flat `roles` array off every verified ID token, and the middleware
attaches those strings to `Identity.Roles` — refreshing them against the IdP through
`offline_access` whenever the cached copy is older than `ClaimsTTL`.

The strings are opaque to `porte`. It transports them and keeps them fresh and never assigns them
meaning: what an `admin` may do is the app's, through `Identity.HasRole`.

Turning it on costs **one query per authenticated request** — the identity row the roles are
cached on — on top of the session lookup. That is why it is opt-in rather than always-on: an app
with no roles pays exactly what it pays today.

**The silent-deny trap.** The scope must be attached to the provider's property mappings *and*
requested by the client, and authentik's own documentation carries the failure: when either half
is missing the claim simply never arrives, and every rule denies, silently, with no error
anywhere. A silent deny in the auth path is the worst failure mode available, so `porte` catches
it in two places, because only half of it is checkable at boot:

- **At startup**, `oidc.New` reads `scopes_supported` from the discovery document and refuses to
  boot when the configured scope is not among them. A provider that advertises no
  `scopes_supported` at all is warned about and allowed through — there is nothing to check
  against, and refusing would break every non-Authentik issuer.
- **On the first callback**, a granted scope that produced no `roles` claim fails the login with
  a message saying the provider is missing its scope mapping. The absence is only observable
  once a token exists, which is why it cannot be a boot check.

**The claim must be filtered per application by the scope mapping.** This is the part that is easy
to get wrong on the provider side, where `porte` cannot help. A mapping that emits every group a
user belongs to puts one app's access inside another app's token: Nuage's ID token would name
`sablier-admin`, and any app that matched loosely, logged the claim, or forwarded it would be
leaking Sablier's authorization model to Nuage's operators. Emit the roles for *this* application,
stripped of any app prefix — that is what makes `Identity.HasRole("admin")` an exact comparison
with nothing to parse, and it is least privilege for free.

The producing half — a small Python scope mapping, parameterised by app slug — lives in the
`authentik-config` repo next to the existing expression policies. Until it is deployed,
`ClaimsScope` cannot be enabled against the suite's provider.

## `local.Config`

The local login's policy, separate from `porte.Config` because it is `porte/local`'s and an app
that never signs anyone in with a password never constructs it.

| Field | Default | What it does |
|---|---|---|
| `AllowRegistration` | `false` | Whether `POST /auth/register` is mounted, and whether registration stays open past the first account |
| `MinPasswordLength` | `12` | A length floor, applied by `Register` and `SetPassword` |

`AllowRegistration` is two rules under one name, and the difference shows only when an app calls
`Register` from its own handler rather than mounting the route. `Mount` does not register
`/auth/register` when it is false. `Register` itself, when it is false, still allows the **first**
account and refuses every later one: locking an empty instance out of itself is not a security
property, and every app in the suite already carries that exception. Journal forwards the same
flag to `GET /auth/config` as `allow_registration` through `Deps.ConfigExtra`, which is how its
frontend knows whether to draw a sign-up link.

`MinPasswordLength` is a length and nothing else. No character classes: they push people towards
`P@ssw0rd1`, and they buy nothing that length does not.

The argon2id parameters are **not** configurable — 64 MiB, three passes, two lanes. They are
copied from the apps rather than chosen, so every hash already in a Facile database keeps
verifying and adopting `porte/local` is a code change rather than a password reset. The PHC
encoding stores them per hash, so raising the cost later is a change to the constants that
verifies old hashes at their old settings instead of locking everyone out.

## Constants

These are frozen, not configurable. One spelling across the suite is the entire point.

| Constant | Value | What it does |
|---|---|---|
| `SessionCookieName` | `session` | The base name of the browser session cookie |
| `CSRFHeaderName` | `X-Facile-CSRF` | Second lock on the cookie transport |

`SessionCookieName` is taken from the two apps that already ship the cookie transport. It is the
**base** name: over https the cookie is written and read as `__Host-session`, and the bare
spelling is read only during a migration. See the cookie flags below — adopting their name buys
a shorter migration, not a free one.

`CSRFHeaderName` carries **any non-empty value** — its presence is the whole signal. A browser
will not attach a custom header to a simple cross-site request without a preflight, so there is
nothing to mint, distribute, or rotate. `SameSite=Lax` stops cross-site form posts; this stops
the rest.

## Cookie flags

Set by the implementation, not configurable:

```
Name=__Host-session  Path=/  MaxAge=SessionTTL  HttpOnly  SameSite=Lax  Secure=<derived>
```

`Secure` is derived from `Config.HTTPS() || r.TLS != nil || X-Forwarded-Proto == https`. The
per-request half is there because behind Traefik the request reaching the Go process is plain
HTTP while the browser's connection is not, so testing the success URL alone gets it wrong in
exactly the deployment topology the suite runs. The configuration half overrides it **upward and
never downward**: an app whose redirect URL is https is served over https, and a proxy that was
misconfigured into dropping `X-Forwarded-Proto` must not be able to talk `porte` into shipping
the session cookie in the clear.

### The `__Host-` prefix

Both cookies `porte` writes — the session and the short-lived `oidc_state` flow cookie — are
written under `__Host-session` and `__Host-oidc_state` whenever the connection is secure. A
browser accepts a `__Host-` cookie only from a request that is Secure, with `Path=/` and no
`Domain`, so such a cookie is necessarily host-locked and the server can tell it apart from a
look-alike.

That is the only cookie attribute an attacker on a sibling host cannot forge, and this suite is
exactly the shape that needs it: every app sits under one parent domain, so without the prefix a
plain cookie named `session` scoped to `Domain=facile.studio` is indistinguishable at the server
from the app's own host-only one. One XSS, one rogue app or one subdomain takeover then fixes a
victim into an attacker's session on all the others. Eight bytes in front of the name close it.

The prefix is dropped over plain http, because a browser rejects it there outright and local
development would stop working. Over http the bare name is therefore the only name read.

**Over https the unprefixed name is not read at all**, unless `AcceptLegacyCookie` is set. This
is the part that is easy to get wrong: a reader that always falls back to the bare name accepts
precisely the cookie the attack plants, and the prefix becomes decoration. It is worst against a
user who is *not* signed in, who has no prefixed cookie for a preference order to prefer, and
who is therefore silently signed in as the attacker.

`AcceptLegacyCookie` exists because an app adopting `porte` has users holding its own pre-`porte`
`session` cookie. Turn it on for one `SessionTTL` — after that every surviving session was issued
by `porte` and carries the prefix — then turn it off. There is no shorter honest migration: a
reader cannot tell a legacy cookie from a forged one, which is the whole reason the prefix is
worth having. A logout expires both spellings regardless, so it never leaves a legacy cookie
behind on the request meant to migrate the user off it.

## What is not configurable, on purpose

- **The scopes.** `openid email profile offline_access`, plus `ClaimsScope` when set.
  `offline_access` is what makes a silent claim refresh possible without a second login, and
  every app already requests all four.
- **Credentials in query parameters.** `porte` reads the session cookie and the `Authorization`
  header, and nothing else. A credential in a URL is copied into access logs, `Referer` headers
  and browser history.

  The honest objection is that two browser APIs cannot set headers at all: `EventSource` and a
  plain navigation to a download URL. Both exist in the suite today and both are why a `?token=`
  was added in the first place. **The cookie transport answers them rather than banning them** —
  `EventSource` and navigations send cookies automatically, so the query parameter stops being
  needed the moment the cookie lands. That is a second argument for the cookie beyond XSS, and
  it means an app adopting `porte` deletes its query-parameter path instead of porting it.
- **The hash.** Session tokens are random, opaque, and stored hashed. There is no option to
  store them in the clear and no option to issue a self-contained JWT instead: an opaque token
  is revocable by construction, which is the property back-channel logout depends on.
