package spacestest

import (
	"context"
	"errors"
	"testing"

	"github.com/FacileStudio/porte/spaces"
)

func testAbsenceIsError(t *testing.T, f fixture) {
	ctx := context.Background()

	if _, err := f.guard.Store.Membership(ctx, SpaceA, UserOutsider); !errors.Is(err, spaces.ErrNotMember) {
		t.Fatalf("Store.Membership for a missing row = %v, want ErrNotMember", err)
	}
	if _, err := f.guard.Store.Membership(ctx, SpaceB, UserAdmin); !errors.Is(err, spaces.ErrNotMember) {
		t.Fatalf("Store.Membership across spaces = %v, want ErrNotMember", err)
	}

	count, err := f.guard.Store.CountRole(ctx, SpaceB, f.top)
	if err != nil || count != 2 {
		t.Fatalf("Store.CountRole(B, %q) = %d, %v, want 2, nil", f.top, count, err)
	}
	count, err = f.guard.Store.CountRole(ctx, SpaceA, f.top)
	if err != nil || count != 1 {
		t.Fatalf("Store.CountRole(A, %q) = %d, %v, want 1, nil", f.top, count, err)
	}

	if held, err := f.guard.Spaces(ctx, UserOutsider); err != nil || len(held) != 0 {
		t.Fatalf("Spaces(non-member) returned %d memberships, %v, want 0, nil", len(held), err)
	}
}

// testRowsAreFaithful is the invariant counting rows cannot see: a store that
// blanks the ids, or promotes every row it lists, answers the right number of
// rows and the wrong ones.
func testRowsAreFaithful(t *testing.T, f fixture) {
	ctx := context.Background()

	for _, want := range f.rows {
		got, err := f.guard.Store.Membership(ctx, want.SpaceID, want.UserID)
		if err != nil {
			t.Fatalf("Store.Membership(%s, %s) = %v, want the seeded row", want.SpaceID, want.UserID, err)
		}
		if got != want {
			t.Errorf("Store.Membership(%s, %s) = %+v, want %+v: every field comes from the row",
				want.SpaceID, want.UserID, got, want)
		}
	}

	for _, userID := range []string{UserOwner, UserAdmin, UserMember, UserCoOwner, UserOutsider} {
		testListedRows(t, f, userID)
	}
}

func testListedRows(t *testing.T, f fixture, userID string) {
	ctx := context.Background()

	want := rowsFor(f, userID)

	listed, err := f.guard.Store.Memberships(ctx, userID)
	if err != nil {
		t.Fatalf("Store.Memberships(%s) = %v", userID, err)
	}
	if diff := compare(listed, want); diff != "" {
		t.Errorf("Store.Memberships(%s): %s", userID, diff)
	}

	held, err := f.guard.Spaces(ctx, userID)
	if err != nil {
		t.Fatalf("Spaces(%s) = %v", userID, err)
	}
	if diff := compare(held, want); diff != "" {
		t.Errorf("Spaces(%s): %s", userID, diff)
	}
}

func rowsFor(f fixture, userID string) []spaces.Membership {
	var out []spaces.Membership
	for _, row := range f.rows {
		if row.UserID == userID {
			out = append(out, row)
		}
	}
	return out
}

func compare(got, want []spaces.Membership) string {
	set := make(map[spaces.Membership]int, len(want))
	for _, row := range want {
		set[row]++
	}
	for _, row := range got {
		if set[row] == 0 {
			return "returned " + describe(got) + ", want exactly " + describe(want) +
				"; ids must be populated from the row and the role preserved"
		}
		set[row]--
	}
	if len(got) != len(want) {
		return "returned " + describe(got) + ", want exactly " + describe(want)
	}
	return ""
}

func describe(rows []spaces.Membership) string {
	if len(rows) == 0 {
		return "no rows"
	}
	out := ""
	for i, row := range rows {
		if i > 0 {
			out += ", "
		}
		out += "{" + row.SpaceID + " " + row.UserID + " " + string(row.Role) + "}"
	}
	return "[" + out + "]"
}
