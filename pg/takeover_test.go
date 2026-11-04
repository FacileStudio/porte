package pg_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/FacileStudio/porte"
)

// leftovers counts the rows a purged holder could still use.
func leftovers(t *testing.T, db *sql.DB, userID int64) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, table := range []string{"porte_sessions", "porte_login_codes", "porte_magic_links"} {
		var n int
		if err := db.QueryRowContext(context.Background(), `SELECT count(*) FROM `+table+` WHERE user_id = $1`, userID).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			counts[table] = n
		}
	}
	return counts
}

// identitiesOf lists provider:subject for every identity on a user.
func identitiesOf(t *testing.T, db *sql.DB, userID int64) []string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(),
		`SELECT provider || ':' || subject FROM porte_identities WHERE user_id = $1 ORDER BY 1`, userID)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var identity string
		if err := rows.Scan(&identity); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, identity)
	}
	return out
}

// plant gives a user one row in every table a holder signs in with.
func plant(t *testing.T, db *sql.DB, userID int64) {
	t.Helper()
	for _, statement := range []string{
		`INSERT INTO porte_sessions (token_hash, user_id) VALUES ('h1', $1)`,
		`INSERT INTO porte_sessions (token_hash, user_id, label) VALUES ('h2', $1, 'api')`,
		`INSERT INTO porte_login_codes (code_hash, user_id, expires_at) VALUES ('c1', $1, now() + interval '1 hour')`,
		`INSERT INTO porte_magic_links (token_hash, user_id, created_at, expires_at) VALUES ('m1', $1, now(), now() + interval '1 hour')`,
	} {
		if _, err := db.ExecContext(context.Background(), statement, userID); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// TestAVerifiedLoginPurgesAPreRegisteredRow: a stranger registers the
// victim's address with a password and another IdP, then the victim signs in.
// Nothing the stranger held survives.
func TestAVerifiedLoginPurgesAPreRegisteredRow(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	squatter, err := store.Users().CreateFromPassword(ctx, "victim@example.test", "Attacker")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, identity := range []porte.StoredIdentity{
		{UserID: squatter, Provider: porte.ProviderLocal, Subject: porte.LocalSubject(squatter), PasswordHash: "x"},
		{UserID: squatter, Provider: "https://other.idp", Subject: "att"},
	} {
		if err := store.Identities().Save(ctx, identity); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	plant(t, db, squatter)
	victim, err := store.Users().UpsertFromOIDC(ctx, claims("victim-sub", "victim@example.test", true))
	if err != nil || victim != squatter {
		t.Fatalf("victim landed on %d (row %d): %v", victim, squatter, err)
	}
	if left := leftovers(t, db, victim); len(left) != 0 {
		t.Errorf("the purge left %v", left)
	}
	if got := identitiesOf(t, db, victim); len(got) != 1 || got[0] != "https://sso.test:victim-sub" {
		t.Errorf("identities after the purge: %v", got)
	}
}

// TestASquatIsNeitherATakeoverNorALockout: an unverified first login takes an
// address; its verified owner then signs in and evicts it.
func TestASquatIsNeitherATakeoverNorALockout(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	squatter, err := store.Users().UpsertFromOIDC(ctx, claims("sub-att", "victim@example.test", false))
	if err != nil {
		t.Fatalf("squat: %v", err)
	}
	plant(t, db, squatter)
	victim, err := store.Users().UpsertFromOIDC(ctx, claims("sub-vic", "victim@example.test", true))
	if err != nil {
		t.Fatalf("the owner was locked out: %v", err)
	}
	if got := identitiesOf(t, db, victim); len(got) != 1 || got[0] != "https://sso.test:sub-vic" {
		t.Errorf("identities after the eviction: %v", got)
	}
	if left := leftovers(t, db, victim); len(left) != 0 {
		t.Errorf("the squatter kept %v", left)
	}
	again, err := store.Users().UpsertFromOIDC(ctx, claims("sub-att", "victim@example.test", false))
	if err == nil && again == victim {
		t.Error("the evicted squatter signed back into the owner's account")
	}
}

// TestAnUnverifiedReloginKeepsTheVerifiedFlag: a subject match never clears
// email_verified, so the row is not re-opened to a takeover.
func TestAnUnverifiedReloginKeepsTheVerifiedFlag(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	owner, err := store.Users().UpsertFromOIDC(ctx, claims("sub-v", "flip@example.test", true))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := store.Users().UpsertFromOIDC(ctx, claims("sub-v", "flip@example.test", false)); err != nil {
		t.Fatalf("unverified relogin: %v", err)
	}
	var verified bool
	if err := db.QueryRowContext(ctx, `SELECT email_verified FROM porte_users WHERE id = $1`, owner).Scan(&verified); err != nil || !verified {
		t.Fatalf("email_verified = %v after an unverified relogin (%v)", verified, err)
	}
	other := claims("sub-x", "flip@example.test", true)
	other.Provider = "https://other.idp"
	if _, err := store.Users().UpsertFromOIDC(ctx, other); err != nil {
		t.Fatalf("other provider: %v", err)
	}
	if identityCount(t, db, owner, "sub-v") != 1 {
		t.Error("a verified login from another provider purged the owner's identity")
	}
}

// TestALegacyMixedCaseRowNeverResolvesToItsLowercaseTwin: rows written before
// lowercasing can collide; the login must fail rather than land elsewhere.
func TestALegacyMixedCaseRowNeverResolvesToItsLowercaseTwin(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	var legacy int64
	if err := db.QueryRowContext(ctx,
		`INSERT INTO porte_users (email, email_verified) VALUES ('Case@Example.test', true) RETURNING id`).Scan(&legacy); err != nil {
		t.Fatalf("legacy row: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO porte_identities (user_id, provider, subject) VALUES ($1, 'https://sso.test', 'sub-c')`, legacy); err != nil {
		t.Fatalf("legacy identity: %v", err)
	}
	twin, err := store.Users().CreateFromPassword(ctx, "case@example.test", "L")
	if err != nil {
		t.Fatalf("twin: %v", err)
	}
	if got, err := store.Users().UpsertFromOIDC(ctx, claims("sub-c", "Case@Example.test", true)); err == nil && got != legacy || got == twin {
		t.Fatalf("the legacy subject resolved to %d (legacy %d, twin %d): %v", got, legacy, twin, err)
	}
}
