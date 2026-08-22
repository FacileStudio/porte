# porte — Development

Local setup, the quality gate, and how this repo versions itself.

## Setup

```sh
git clone git@github.com:FacileStudio/porte.git
cd porte
mise install
```

`mise.toml` pins Go 1.25 — the floor `go.mod` documents, and CI pins the same number exactly.
Building only on a newer toolchain is how a construct the floor does not have reaches a consumer
unnoticed.

The floor was meant to be 1.24, matching `tronc` and `caisse`, on the principle that a library
floors low so a consumer can be newer. `go-oidc` v3.20 requires Go >= 1.25, so the choice was
made by the dependency. That costs nothing here: the six consuming apps moved to 1.25 in Phase 2
and `tronc/migrate` already declares 1.25.7.

## The quality gate

```sh
mise run check
```

That runs `scripts/check.sh`: `gofmt -l`, `go vet ./...`, `go test -race ./...`, then
`golangci-lint`. The script depends on nothing but a `go` on the path and is **not** invoked
through mise internally, on purpose — a git hook must not require a task runner to be installed.

```sh
mise run test      # tests only
mise run format    # rewrite formatting in place
```

`scripts/check.sh` reports; it never rewrites a file. Use `mise run format` for that.

The gate degrades honestly rather than silently: with no `golangci-lint` on the path it prints
that it skipped the lint pass, and with `PORTE_TEST_DATABASE_URL` unset it prints that the `pg`
tests were skipped. CI runs both, so a local skip is a convenience and never a way to land
something broken.

## Hooks

`mise install` wires the git hooks through lefthook, so the clone sequence in Setup above is
all a fresh checkout needs.

`lefthook.yml` pulls the shared conventional-commit check from
[FacileStudio/hooks](https://github.com/FacileStudio/hooks), pinned by tag, so a commit
subject has to read `type(scope): summary`. `scripts/check.sh` is unchanged and still the
gate, now run as the local `pre-push` job.

Bypass once with `git push --no-verify`.

## Tests

```sh
go test -race ./...
```

The contract package has no behaviour to speak of, and its tests cover the parts that do carry
logic: `Config.Validate` naming every missing variable, `Scopes` appending the claims scope only
when configured, `Resolved` filling zero durations, `DisplayName` precedence, exact role
matching, a zero `ExpiresAt` never expiring, and a never-synced claim reading as stale.

The tests live in package `porte_test`, not `porte`. They exercise the package the way a
consuming app does, which is the only way a contract test proves anything about a contract.

`porte/pg` needs a real PostgreSQL:

```sh
export PORTE_TEST_DATABASE_URL=postgres://porte:porte@localhost:5432/porte_test?sslmode=disable
```

Without it those tests skip themselves, silently and with a passing exit code, so CI provides a
PostgreSQL 16 service rather than trusting them untested. They are worth the service: every
interesting behaviour in that package is PostgreSQL's own — a conditional `UPDATE` settling a
race between two exchanges of the same login code, `ON CONFLICT` resolving two first logins into
one user, an untyped `interval` parameter failing to resolve an operator. A fake would test the
fake.

`porte/oidc` needs nothing. Its flow tests run against a conformant identity provider built in
process: it signs RS256 tokens behind a real JWKS, and its token endpoint enforces PKCE, the
redirect URI and client authentication rather than trusting the client to have sent them. That
is what makes them worth writing — a fake issuer that echoes whatever it is handed cannot fail a
kit that dropped its PKCE verifier.

## Layout

```
porte.go       Config, route paths, wire shapes, the frozen constants
identity.go    Identity, Claims, TokenSet, StoredIdentity, UserStore, IdentityStore
session.go     Session, LoginCode, SessionStore, LoginCodeStore, AvatarStore
token.go       NewToken, HashToken, SecureCompare
oidc/          the engine: the flow, the seven routes, the middleware, the avatar guard
pg/            the identity tables and the four stores over them
docs/          Configuration, development, API
```

`porte/espace` (v0.4) arrives the same way, as a subpackage sharing this repo's tags — the
pattern `tronc/migrate`, `tronc/testdb` and `caisse/pg` already use. An app that does not need
spaces simply does not import `espace`.

**No GORM.** All six consuming apps use it, but forcing an ORM is a heavier commitment than
anything the suite shares today, and it is what pushed `tronc` to split `migrate` and `testdb`
into separate modules. `database/sql` keeps everything in one module.

**No dependencies in the root package.** The contract is standard library only, deliberately —
see [api.md](api.md). Adding an import there is a decision, not a convenience: it is what an
app's stores and domain code compile against, and `porte/oidc` exists as a separate package
precisely so that code never sees `go-oidc`.

## Versioning

Semver from `main`. While on `v0`, a breaking change bumps the **minor**.

Record decisions in [CHANGELOG.md](../CHANGELOG.md) with their reasoning. The reasoning is the
part that stops a future session from undoing a deliberate choice — this repo has already had
three of its own claims go stale in a day, and the ones that survived contact with the source
survived because they said why.

## Before changing the contract

Read [SPEC.md](../SPEC.md) §3 first. It lists the decisions that are settled and the evidence
each was taken on. Several of them argue against the obvious alternative, and the spec's §12
lists the prior art that disagrees, so a reversal can be argued rather than assumed.

Six apps and their frontends will depend on these shapes. The contract is the part that is
expensive to get wrong, which is why it was written from a diff of all six implementations
rather than from one.
