#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== Format check ==="
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
  echo "Unformatted files:"
  echo "$unformatted"
  exit 1
fi
echo "OK"

echo "=== Vet ==="
go vet ./...
echo "OK"

echo "=== Lint ==="
golangci-lint run
echo "OK"

echo "=== Tests ==="
go test ./... -count=1 -race
echo "OK"

echo ""
echo "All checks passed."
