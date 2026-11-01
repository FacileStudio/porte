package magiclink

import (
	"context"
	"strings"
	"testing"
)

func TestAPanickingMailerDoesNotTakeTheProcessDown(t *testing.T) {
	r := newRig(t, Config{})
	r.kit.deps.Send = func(context.Context, string, string) error { panic("smtp exploded") }
	r.request(t, "camille@facile.studio", "")

	if !strings.Contains(r.logs.String(), "smtp exploded") {
		t.Fatalf("the panic was not logged: %q", r.logs.String())
	}
}

func TestNewRequiresAllowSoAForgottenCheckCannotSignInABannedUser(t *testing.T) {
	r := newRig(t, Config{})
	deps := r.kit.deps
	deps.Allow = nil
	if _, err := New(Config{}, deps); err == nil {
		t.Fatal("a kit with no Allow must not boot")
	}
}

func TestADisplayNameFormMailsTheBareAddress(t *testing.T) {
	r := newRig(t, Config{})
	r.request(t, "Camille <Camille@Facile.Studio>", "")

	mails := r.mail.mails()
	if len(mails) != 1 || mails[0].to != "camille@facile.studio" {
		t.Fatalf("want one mail to the bare address, got %+v", mails)
	}
}
