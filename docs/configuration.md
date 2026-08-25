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
| `OIDC_MACHINE_AUDIENCE` | no | — | Audience a bearer JWT must carry to authenticate offline against the provider's JWKS on the `Authorization` header path. **Its presence is what enables bearer-JWT verification.** Set it to **this app's own client id**, which is what a service account's token is addressed to |
| `OIDC_CLI_AUDIENCE` | no | — | Audience a CLI's device-grant token must carry at `POST /auth/oidc/device/exchange`. **Its presence is what mounts that route**, and it alone. Set it to **the CLI's client id**, `facile-cli` for the suite |
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
| `MachineAudience` | — | Audience a bearer JWT must carry to be verified offline on the header path. Empty disables that branch; requires `Issuer`. See [Bearer JWTs from the issuer](#bearer-jwts-from-the-issuer) below |
| `CLIAudience` | — | Audience a device-grant token must carry at the device exchange. Empty leaves that route unmounted; requires `Issuer`. Never the same value as `MachineAudience` |
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

## Bearer JWTs from the issuer

Setting `OIDC_MACHINE_AUDIENCE` gives the session manager a second bearer verifier. A bearer
that parses as three dot-separated segments is verified offline — signature against the
provider's JWKS, then `iss`, `aud`, `exp` and, when present, `nbf` and `iat` — and never touches
the hashed-session lookup. Anything else is authenticated exactly as before, so an opaque
token's behaviour does not move.

The variable is named for machine tokens because that is what it holds: this app's own client
id, the audience a service account's token is addressed to. It admits any principal the issuer
signs for that audience, a human included, so a token minted for this app authenticates as
whoever it names.

It is **not** how a CLI signs in. The suite CLI's token is addressed to `facile-cli`, not to this
app, and it is spent at
[the device exchange](#the-device-exchange-and-the-second-audience-it-needs) rather than on this
path. Setting this variable to `facile-cli` to get CLI login would break every service-account
token instead, which is why the exchange has its own `OIDC_CLI_AUDIENCE`.

The rules the branch lives by:

- **A failed verification is refused, never fallen through.** A token that parses as a JWT and
  fails *is* an answer; giving it a second chance with the session lookup would mean a bad
  token's only cost was being unrecognized.
- **The token resolves to a local account, or it is refused.** `sub` is matched against
  `porte_identities` on `(issuer, subject)` — the same key the login callback and back-channel
  logout use, never the email address. A subject with no row has never signed in here, and porte
  does not create an account from a bearer: the callback owns account creation because it is the
  path holding a verified email.
- **The identity lookup is the deactivation lever.** There is no session row behind a verified
  token, so revoking sessions does not reach one and `SessionID` is zero. What does reach one is
  `IdentityStore.Find`: an app that deactivates an account by making `Find` answer `ErrNotFound`
  locks it out of this path on the next request. An app that leaves the row readable keeps
  admitting the token until it expires, so the issuer's access-token lifetime is the real bound.
- **Roles come from the token, not from the cached row.** The row holds what the provider said
  during the last browser login; the token holds what it says now, already filtered for this
  client. A provider that emits no roles claim therefore leaves a bearer caller with no roles
  rather than with yesterday's — closed rather than open.
- **Keys are cached for an hour** (`DefaultCacheTTL` in `porte/oidc/jwt`, roughly one token
  lifetime) and refetched once on an unknown kid before refusing, so a rotation does not wait
  out the TTL. That refetch is rate limited to one per `minRefetchInterval` (30s), because the
  kid is read before any signature is checked and would otherwise buy an unauthenticated caller
  one outbound fetch per request, aimed at the provider every app shares.
- **Introspection is deliberately out of scope.** Offline verification is what makes the check
  free; a per-request call to the issuer would reintroduce the dependency this exists to remove.

### The device exchange, and the second audience it needs

`OIDC_CLI_AUDIENCE` mounts `POST /auth/oidc/device/exchange`. A CLI trades the access token it
already holds from the provider's device grant (RFC 8628) for this app's own session token:

```
POST /api/auth/oidc/device/exchange
{"access_token": "<the token the provider issued>"}
→ 200 {"user_id": "42", "token": "<this app's session>"}
```

This is what makes one `facile login` serve every tool. The CLI runs the device grant once,
gets one token, and trades it at each tool, because writing the provider's token into the slot
where a CLI keeps its own session is a login that stops working when that token expires.

**The two audiences are different settings holding different values, and neither substitutes for
the other.**

```
OIDC_MACHINE_AUDIENCE=courrier      # this app's own client id, for service accounts
OIDC_CLI_AUDIENCE=facile-cli        # the CLI's client id, for the device exchange
```

A service account's token is addressed to one app: Registre's `suite-ci` declares
`audiences: [courrier]`, so courrier checks `courrier`. The CLI's token is addressed to the CLI
and presented at every tool, so it carries `aud: ["facile-cli"]` and every app checks that same
value. An app forced to spell one of them in a single variable would have to choose, and an app
that chose the CLI would start refusing every service-account token it had been accepting, with
nothing in its own configuration having changed meaning. That is why there are two fields.

**Setting `OIDC_CLI_AUDIENCE` does not put a CLI token on the header path.** It builds a second
verifier that serves this route and nothing else; it never reaches the session manager. So a
`facile-cli` token is not a credential on every `RequireAuth` route, and the only way it buys
anything here is by being exchanged, which leaves a session row the app can list, expire and
revoke. A verified bearer JWT leaves no row at all, which is the difference that matters.

**Leaving `OIDC_CLI_AUDIENCE` empty means the route is not mounted and answers 404**, which is
deliberate rather than a gap. An app with no CLI audience cannot tell a Registre token from a
forgery, so it must not pretend to serve the exchange, and 404 is precisely the signal
`facile login` reads as "this app has not shipped it" before falling back to the loopback flow.
The corollary binds an app that *does* mount it: the CLI probes with a POST carrying an empty
body, so every bad request must be refused on its merits (400 or 401) and never with a 404.

Everything the header path refuses, the exchange refuses identically, with one 401 and one
message. That covers bad signature, wrong issuer, wrong audience, expired, not yet valid,
unknown kid, no subject, and a subject with no row in `porte_identities`. A token addressed to
`OIDC_MACHINE_AUDIENCE` is refused here too, and the reverse. No account is created here: a
verified subject nobody has seen before is refused, because account creation belongs to the
login callback, which is the path that holds a verified email; provisioning from a bearer would
let anyone the provider will mint a token for materialise an account in every app at once.

**What this does not contain.** A stolen or phished `facile-cli` token can still be exchanged
for a durable session at every app that trusts it, as whoever the token names. `facile-cli` is a
public client, so anyone can start its device grant; what stands between a stranger and a
session here is the human approving the code at the provider and the requirement that the
subject already hold a local account. Bounding the rest is back-channel logout's job, and no app
in the suite registers a `backchannel_logout_uri` today, so that bound is not in place yet.

No CSRF header is required, and that is not an oversight. The suite's default is the opposite
because the default transport is a cookie a browser attaches on its own; here there is no
ambient credential to abuse, since the caller must put a token it holds into the request body,
which a cross-site form cannot do.
