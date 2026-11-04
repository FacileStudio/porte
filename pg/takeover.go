package pg

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"

	"github.com/FacileStudio/porte"
)

// refusal says why claims that matched no account cannot take its address.
func refusal(claims porte.Claims) error {
	if !claims.EmailVerified {
		return fmt.Errorf(
			"porte/pg: %s is already registered under a different identity, and the provider did not verify the address, so porte will not link them",
			claims.Email)
	}
	return fmt.Errorf(
		"porte/pg: %s already belongs to another identity of this provider, so porte will not link a second one",
		claims.Email)
}

// byVerifiedEmail locks the row holding the address, then checks in a fresh
// statement that no identity of this provider was linked to it meanwhile. A
// row whose address was never verified matches even when it holds one: its
// holder never proved the address, and resolveOrCreate purges it.
func byVerifiedEmail(ctx context.Context, tx *sql.Tx, claims porte.Claims) (match, bool, error) {
	found := match{byEmail: true}
	var verified, linked bool
	err := tx.QueryRowContext(ctx,
		`SELECT id, email_verified FROM porte_users WHERE email = $1 FOR UPDATE`,
		claims.Email).Scan(&found.userID, &verified)
	if stderrors.Is(err, sql.ErrNoRows) {
		return found, false, nil
	}
	if err == nil {
		err = tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM porte_identities WHERE user_id = $1 AND provider = $2)`,
			found.userID, claims.Provider).Scan(&linked)
	}
	if err != nil {
		return found, false, fmt.Errorf("porte/pg: resolve user by email: %w", err)
	}
	found.unverified = !verified
	return found, found.unverified || !linked, nil
}

// purge removes everything a holder of an unverified row could still use.
func purge(ctx context.Context, tx *sql.Tx, userID int64) error {
	for _, table := range []string{"porte_identities", "porte_sessions", "porte_login_codes", "porte_magic_links"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE user_id = $1", userID); err != nil {
			return fmt.Errorf("porte/pg: purge %s: %w", table, err)
		}
	}
	return nil
}
