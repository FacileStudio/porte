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

### `SSO_ONLY` does not reject, it does not register

When `SSO_ONLY` is true the local password routes are never mounted. They do not return 403 —
they are not there. There is no endpoint to probe and no handler to reach by mistake.

## Config

| Field | Default | What it does |
|---|---|---|
| `Issuer` | — | Empty disables OIDC entirely. `Enabled()` reports it |
| `ClientID` | — | Required once `Issuer` is set |
| `ClientSecret` | — | Required once `Issuer` is set |
| `RedirectURL` | — | Required once `Issuer` is set |
| `SuccessURL` | — | Required once `Issuer` is set |
| `SSOOnly` | `false` | Local password routes are not registered |
| `ClaimsScope` | — | Scope carrying the `roles` claim. Empty disables claims handling |
| `SessionTTL` | `30 days` | Browser session lifetime |
| `ClaimsTTL` | `5 minutes` | How long a cached role claim is trusted |
| `LoginCodeTTL` | `60 seconds` | Window for a CLI to exchange its one-time code |

`Config.Resolved()` returns a copy with zero durations replaced by their defaults, so the rest
of the implementation never repeats the fallback. Call it once at construction.

### The defaults are measurements, not taste

Each number is what the apps already do, not a preference:

- **30 days** is the session lifetime every app hardcodes today.
- **60 seconds** is the existing CLI login code window.
- **5 minutes** is the existing `profile_synced_at` rate limit, reused for claims on purpose.
  One refresh cadence is easier to reason about than two, and it means a role revoked in the IdP
  stops mattering within five minutes while the IdP sees at most one refresh per user per five
  minutes rather than one per request.

### `ClaimsScope` and the silent-deny trap

Claims are **off** unless `ClaimsScope` is set. No app reads claims today, so leaving it unset
regresses nothing.

When it is set, it must name a scope that the Authentik provider actually has attached as a
property mapping. authentik's own documentation carries the trap: group-based authorization
needs the scope attached to the provider *and* requested by the client, and **if either half is
missing the rules silently deny everyone**. A silent deny in the auth path is the worst failure
mode available, so `porte` verifies at startup that the scope was granted and a `roles` claim
actually arrived, and refuses to boot naming the missing half.

The producing half — a small Python scope mapping, parameterised by app slug — lives in the
`authentik-config` repo next to the existing expression policies.

## Constants

These are frozen, not configurable. One spelling across the suite is the entire point.

| Constant | Value | What it does |
|---|---|---|
| `SessionCookieName` | `session` | The browser session cookie |
| `CSRFHeaderName` | `X-Facile-CSRF` | Second lock on the cookie transport |

`SessionCookieName` is taken from the two apps that already ship the cookie transport, so
adopting `porte` does not log their users out a second time.

`CSRFHeaderName` carries **any non-empty value** — its presence is the whole signal. A browser
will not attach a custom header to a simple cross-site request without a preflight, so there is
nothing to mint, distribute, or rotate. `SameSite=Lax` stops cross-site form posts; this stops
the rest.

## Cookie flags

Set by the implementation, not configurable:

```
Name=session  Path=/  MaxAge=SessionTTL  HttpOnly  SameSite=Lax  Secure=<derived>
```

`Secure` is derived from `r.TLS != nil || X-Forwarded-Proto == https` rather than from the
success URL's scheme. Behind Traefik the request reaching the Go process is plain HTTP while the
browser's connection is not, so testing the URL gets it wrong in exactly the deployment topology
the suite runs.

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
