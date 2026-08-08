#!/usr/bin/env sh
#
# The repository quality gate. Reports, never rewrites (except --format).
#
#   sh scripts/check.sh             gofmt + vet + test + lint
#   sh scripts/check.sh --no-lint   skip golangci-lint
#   sh scripts/check.sh --format    rewrite Go sources in place
#
# porte is a library: there is no client half, so this is the whole gate.
# Deliberately depends on nothing but a `go`. It is NOT invoked through mise:
# `mise run` resolves every tool in the merged config before running any task
# body, so an unrelated broken tool in the user's global config would take this
# gate down with it.
#
# The pg tests will need a real PostgreSQL and skip themselves when
# PORTE_TEST_DATABASE_URL is unset. Export it to run them locally; CI always does.

set -eu

mode="all"
case "${1:-}" in
--no-lint) mode="nolint" ;;
--format) mode="format" ;;
"") ;;
*)
  echo "usage: $0 [--no-lint|--format]" >&2
  exit 2
  ;;
esac

root="$(git rev-parse --show-toplevel)"
cd "$root"

# Resolve the toolchain from GOROOT when it is set. mise exports GOROOT for the
# version this repo pins, but leaves an unrelated `go` earlier on PATH (Homebrew's,
# here), and a go binary driving a different GOROOT fails with
# `compile: version "X" does not match go tool version "Y"`.
if [ -z "${GO:-}" ]; then
  if [ -n "${GOROOT:-}" ] && [ -x "$GOROOT/bin/go" ]; then GO="$GOROOT/bin/go"; else GO=go; fi
fi
if [ -z "${GOFMT:-}" ]; then
  if [ -n "${GOROOT:-}" ] && [ -x "$GOROOT/bin/gofmt" ]; then GOFMT="$GOROOT/bin/gofmt"; else GOFMT=gofmt; fi
fi

if ! command -v "$GO" >/dev/null 2>&1 && [ ! -x "$GO" ]; then
  echo "check: no usable go ('$GO')" >&2
  exit 1
fi

if [ "$mode" = "format" ]; then
  "$GO" fmt ./...
  exit 0
fi

status=0

unformatted="$("$GOFMT" -l . || true)"
if [ -n "$unformatted" ]; then
  echo "gofmt: the following files are not formatted (run 'sh scripts/check.sh --format'):"
  echo "$unformatted"
  status=1
fi

"$GO" vet ./... || status=1
"$GO" test -race ./... || status=1

if [ -z "${PORTE_TEST_DATABASE_URL:-}" ]; then
  echo "check: PORTE_TEST_DATABASE_URL is unset, the pg tests were skipped (CI still runs them)" >&2
fi

if [ "$mode" = "all" ]; then
  # `command -v` is not enough: a mise shim for an uninstalled version is on
  # PATH and resolves, but every invocation of it fails. Probe that the binary
  # actually runs, so an unusable tool skips the pass instead of failing it.
  if golangci-lint version >/dev/null 2>&1; then
    # $GOROOT/bin first, because golangci-lint shells out to `go` and the two
    # have to come from the same install.
    lint_output="$(PATH="${GOROOT:+$GOROOT/bin:}$PATH" golangci-lint run ./... 2>&1)" || lint_status=1
    lint_status="${lint_status:-0}"

    # A golangci-lint whose `go` and whose GOROOT disagree cannot typecheck
    # anything: every import fails with `compile: version "X" does not match
    # go tool version "Y"`, which reads like broken code and is not. That is a
    # broken tool, so it skips like one rather than reporting a false red.
    # It happens when a global mise config pins one Go and the repo pins
    # another, and the shim resolves `go` from somewhere else again.
    if printf '%s' "$lint_output" | grep -q 'does not match go tool version'; then
      echo "check: golangci-lint and its Go toolchain disagree, skipping the lint pass (CI still runs it)." >&2
      echo "check: GOROOT=${GOROOT:-unset}, go=$("$GO" version 2>/dev/null)" >&2
    else
      printf '%s\n' "$lint_output"
      [ "$lint_status" -eq 0 ] || status=1
    fi
  else
    echo "check: no usable 'golangci-lint', skipping the lint pass (CI still runs it)" >&2
  fi
fi

if [ "$status" -ne 0 ]; then
  echo "check failed"
fi
exit "$status"
