#!/usr/bin/env sh
set -eu

if [ "$(go env GOOS)" != "linux" ]; then
  echo "error: the race suite must run in a Linux environment" >&2
  exit 1
fi

if ! command -v "${CC:-cc}" >/dev/null 2>&1; then
  echo "error: a C compiler is required for CGO race instrumentation" >&2
  exit 1
fi

CGO_ENABLED=1 go test -race -p 1 ./...
