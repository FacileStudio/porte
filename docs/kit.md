# porte/kit

`porte/kit` is the sign-in glue an app with its own `users` table used to write by hand. It is
opt-in. It adds no route, no status code, no cookie and no CSRF rule, and it does not touch
`pg.Schema`. The frozen conformance vectors pass with the routes mounted through `kit.Mount`.

## What it owns

| Piece | Replaces |
|---|---|
| `Identity`, `WithIdentity`, `FromContext` | `internal/authcontext` |
| `Store`, a `porte.UserStore` over the app's `users` table | `modules/auth/userstore.go` or `porte.go` |
| `RequireAuth(auth, users)` | `internal/middleware/auth.go` |
| `(*Store).EraseAccount` | the `OnPersonDeleted` callback in `modules/auth/erase.go` |
| `PictureURL`, `(*Store).BackfillPictures` | `internal/oidcavatar` and `BackfillAvatars` |
| `Mount(router, Config)` | the `sessions.Mount(r)` and `kit.Mount(r)` pair |

## Step zero: read `Unwritten()` against your schema

Build the store with `kit.NewStore`, not a `kit.Store` literal. `NewStore` reads the table's
columns once, at construction, and fails when the table or a column `Columns` names is missing.

- **Timestamps.** `Columns.CreatedAt` and `Columns.UpdatedAt` name columns the kit fills itself:
  `now()` into both when it creates an account, `now()` into `UpdatedAt` on every update it makes
  (the sign-in refresh and `BackfillPictures`). Left empty, `NewStore` adopts a timestamp column
  named `created_at` or `updated_at` that has no default, identity or generated expression. That
  is what a GORM `AutoMigrate` table looks like: GORM filled those columns in Go, so the kit's
  insert left them NULL. A column with a database default is left to the database.
- **Everything else.** `store.Unwritten()` lists the nullable columns with no default that the
  kit's insert does not write. They are NULL on every account the kit creates unless `OnCreate`
  fills them. `NewStore` logs them once at warn when `OnCreate` is nil. It is not an error: some
  columns are meant to stay NULL. A NOT NULL column with no default is not listed, because the
  insert fails on it at the first sign-in.

`OnCreate` runs after the insert, in its transaction, so what it writes wins, timestamps
included. A hook that still sets `created_at = now()` writes the value the insert wrote: `now()`
is the transaction's start time.

Decide which unwritten columns the app accepts, fill the others in `OnCreate`, and pin the
decision with one test against the test database:

```go
store, err := kit.NewStore(ctx, kit.Store{DB: sqlDB, Columns: columns, OnCreate: fillNewAccount})
if err != nil || !slices.Equal(store.Unwritten(), []string{"oidc_subject"}) {
	t.Fatalf("unwritten = %v, %v", store.Unwritten(), err)
}
```

A schema change that adds a nullable column then fails this test instead of writing NULL in
production.

## What stays in the app

- The `users` table and its migrations. The kit needs `porte_identities` and the columns
  `Columns` names, nothing else.
- The `/auth/me` response shape.
- Columns the kit does not name. Fill them in `OnCreate`, which runs in the insert's
  transaction. `Unwritten()` lists the ones that would otherwise be NULL.
- The rows an erased person owns. Delete them in `EraseData`.
- The `directory` state store, the token scopes, and every rule beyond "signed in" and
  `is_admin`.

## Wiring

```go
users, err := kit.NewStore(ctx, kit.Store{
	DB:      sqlDB,
	Columns: kit.Columns{Admin: "is_admin"},
	EraseData: func(ctx context.Context, tx *sql.Tx, userID int64) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM monitors WHERE owner_id = $1`, userID)
		return err
	},
})
if err != nil {
	return err
}
requireAuth := kit.RequireAuth(sessions, users)
if err := kit.Mount(api, kit.Config{Sessions: sessions, OIDC: oidcKit}); err != nil {
	return err
}

deletions := &directory.Deletions{OnPersonDeleted: users.EraseAccount, Erase: store.EraseIdentity /* ... */}
```

`users` is also the `Users` dependency of `oidc.New`. Handlers read
`kit.FromContext(r.Context())`. A GORM app passes `db.DB()`.

## Columns

`DefaultColumns()` is `users(id, email, name, avatar_url, locale)` with no admin flag. A zero
field takes its default. `Admin` is the exception: empty means the table has no admin flag.
`CreatedAt` and `UpdatedAt` are detected by `NewStore` when empty (see step zero).

| App | Columns to set |
|---|---|
| Sonde | `Admin: "is_admin"` |
| Casier | none |
| Nuage | `Picture: "oidc_picture_url", Admin: "is_admin"`, colour in `OnCreate` |
| Sablier | `Picture: "oidc_picture_url"`, colour in `OnCreate` |
| Antenne | `Picture: "picture_url"`; its role column and password store stay app-side |

## Rules the store applies

- The email is lowercased and must parse as a bare address, or the sign-in is refused with
  `invalid_argument`.
- An identity already linked to a row resolves to that row.
- Otherwise a verified email links an existing account, unless that account already holds a
  subject of the same provider. An unverified email never links. Both refusals are
  `already_exists`, which porte shows on the login page.
- Otherwise the store creates the account. With `Admin` set, the first account is admin.
- At sign-in the store rewrites the stored email only when the provider marks it verified. This
  is the rule for every app and there is no option to change it: an app that rewrote the email
  on every sign-in (Sablier, Nuage, Casier) adopts this rule with the kit.
- On a linked account the picture is always rewritten, and the name and locale only when the
  provider sent one.
- Every write and every erase runs under one advisory lock, so two first sign-ins cannot both
  become admin.

A provider matches with or without one trailing slash, on either side, in every lookup the kit
makes: the sign-in lookup by subject, the "another subject of the same provider" refusal,
`EraseAccount`, `BackfillPictures` and the invitations subject. A row stored as
`https://sso.facile.studio/` is the same provider as a sign-in presenting
`https://sso.facile.studio`, and the reverse, so an app whose rows mix the two spellings adopts the
store and the erase hook without a data migration. When both spellings are stored for one subject,
the exact spelling wins. The kit never rewrites a stored provider; new rows carry the issuer
exactly as porte/oidc is configured.

## Pending invitations in the user menu

`kit.MountInvitations` registers `GET /me/invitations`, so `GET /api/me/invitations` under the
app's `/api` router. It is opt-in and not part of `Mount`. It answers the signed-in user's pending
space invitations from Registre (`GET {issuer}/api/directory/invitations?sub=`, HTTP Basic with the
directory credentials):

```json
{"count": 1, "href": "https://sso.facile.studio/invitations/0b9c1a2e-..."}
```

`href` is the one invitation's page when `count` is 1, else `{issuer}/spaces`. The route never
fails a page: a user with no Registre identity, a store error, a Registre that is down, busy (503),
slow (over 2 seconds) or answers anything malformed all get 200 `{"count":0}` without `href`, and
the cause is logged at warn. A user with no identity under the issuer is never sent to Registre.
Each answer, failures included, is cached per user for 60 seconds in a bounded cache (10,000
users by default, oldest evicted first), and concurrent requests for one user share one call.

Backend, behind the app's session middleware on its `/api` router:

```go
if err := kit.MountInvitations(api.With(requireAuth), kit.InvitationsConfig{
	Directory:  directory.Client{Issuer: issuer, ClientID: clientID, ClientSecret: clientSecret},
	Identities: porteStore.Identities(),
}); err != nil {
	return err
}
```

`porteStore` is the app's `pg.Store`, built with its `TokenSealer` when it has one. Mount it only
when an issuer is configured: `MountInvitations` refuses an empty issuer, client id or secret. Add
`kit.InvitationsRoute()` to one of the app's documented modules, so the route-coverage test passes.
On tronc v0.16.0 or later, `route.ResponseBody = kit.InvitationsResponse{}` gives it a real schema.

Frontend, muse v0.18.0 or later. `UserMenuInvitations` is `{ count, href, label? }` with `href`
required, and muse draws no row without one, so map an answer without `href` to `null`:

```svelte
<script lang="ts">
	let invitations = $state<{ count: number; href: string } | null>(null);
	$effect(() => {
		fetch('/api/me/invitations').then((r) => (r.ok ? r.json() : null))
			.then((b) => (invitations = b?.href ? { count: b.count, href: b.href } : null))
			.catch(() => (invitations = null));
	});
</script>

<SideBar userMenu={{ ...userMenu, invitations }} />
<MobileNav userMenu={{ ...userMenu, invitations }} />
```

muse shows the Invitations row after Account, a count pill and a dot on the avatar while `count`
is above 0. The absolute Registre `href` opens in a new tab. Nothing changes in the app's CSP or
the seed: the browser never calls Registre.

## Tests

`go test ./kit` runs the route, middleware and invitations tests anywhere; the invitations tests
fake Registre with `httptest`. The store and erase tests need
`PORTE_TEST_DATABASE_URL` and use a schema of their own, `porte_kit_test`.
