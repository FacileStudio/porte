package loopback

import "errors"

// The refusals this package can return. They are sentinels rather than typed
// errors because the only thing a caller does with them is decide what to
// print and what exit code to leave with.
//
// Cancellation is not among them: WaitForCode returns context.Canceled
// unchanged when the caller's context ends, so a CLI that already treats
// Ctrl-C as a quiet exit needs nothing new from here.
var (
	// ErrTimeout means the browser never completed the login inside the
	// window. It is the one failure a CLI should offer to retry rather than
	// report: nothing is broken, the user walked away from an MFA prompt or
	// closed the tab, and the port has since been released.
	ErrTimeout = errors.New("loopback: the browser did not finish the login in time")
)
