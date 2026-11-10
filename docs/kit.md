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

## What stays in the app

- The `users` table and its migrations. The kit needs `porte_identities` and the columns
  `Columns` names, nothing else.
- The `/auth/me` response shape.
- Columns the kit does not name. Fill them in `OnCreate`, which runs in the insert's
  transaction.
- The rows an erased person owns. Delete them in `EraseData`.
- The `directory` state store, the token scopes, and every rule beyond "signed in" and
  `is_admin`.

## Wiring

```go
users := &kit.Store{
	DB:      sqlDB,
	Columns: kit.Columns{Admin: "is_admin"},
	EraseData: func(ctx context.Context, tx *sql.Tx, userID int64) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM monitors WHERE owner_id = $1`, userID)
		return err
	},
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
- On a linked account the picture is always rewritten, the email only when verified, and the
  name and locale only when the provider sent one.
- Every write and every erase runs under one advisory lock, so two first sign-ins cannot both
  become admin.

## Tests

`go test ./kit` runs the route and middleware tests anywhere. The store and erase tests need
`PORTE_TEST_DATABASE_URL` and use a schema of their own, `porte_kit_test`.
