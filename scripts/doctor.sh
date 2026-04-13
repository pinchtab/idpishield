#!/usr/bin/env bash
set -euo pipefail

# doctor.sh — Verify and setup development environment for idpishield
# Interactive: asks before installing anything

BOLD='\033[1m'
ACCENT='\033[38;2;251;191;36m'
INFO='\033[38;2;136;146;176m'
SUCCESS='\033[38;2;0;229;204m'
ERROR='\033[38;2;230;57;70m'
MUTED='\033[38;2;90;100;128m'
NC='\033[0m'

CRITICAL=0
WARNINGS=0
GO_MIN_VERSION="1.23"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ── Helpers ──────────────────────────────────────────────────────────

ok()      { echo -e "  ${SUCCESS}✓${NC} $1"; }
fail()    { echo -e "  ${ERROR}✗${NC} $1"; [ -n "${2:-}" ] && echo -e "    ${MUTED}$2${NC}"; CRITICAL=$((CRITICAL + 1)); }
warn()    { echo -e "  ${ACCENT}·${NC} $1"; [ -n "${2:-}" ] && echo -e "    ${MUTED}$2${NC}"; WARNINGS=$((WARNINGS + 1)); }
hint()    { echo -e "    ${MUTED}$1${NC}"; }

confirm() {
  echo -ne "    ${BOLD}$1 [y/N]${NC} "
  read -r answer
  [[ "$answer" =~ ^[Yy]$ ]]
}

section() {
  echo ""
  echo -e "${ACCENT}${BOLD}$1${NC}"
}

version_ge() {
  local current="${1#v}"
  local minimum="${2#v}"
  local current_major current_minor
  local minimum_major minimum_minor

  IFS='.' read -r current_major current_minor _ <<< "${current}"
  IFS='.' read -r minimum_major minimum_minor _ <<< "${minimum}"

  current_minor=${current_minor:-0}
  minimum_minor=${minimum_minor:-0}

  if [ "$current_major" -ne "$minimum_major" ]; then
    [ "$current_major" -gt "$minimum_major" ]
    return
  fi

  [ "$current_minor" -ge "$minimum_minor" ]
}

# ── Detect package manager ───────────────────────────────────────────

HAS_BREW=false
HAS_APT=false
command -v brew &>/dev/null && HAS_BREW=true
command -v apt-get &>/dev/null && HAS_APT=true

# ── Start ────────────────────────────────────────────────────────────

echo ""
echo -e "  ${ACCENT}${BOLD}🛡️  IDPI Shield Doctor${NC}"
echo -e "  ${INFO}Verifying development environment...${NC}"

section "Go Toolchain"

# ── Go ───────────────────────────────────────────────────────────────

if command -v go &>/dev/null; then
  GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
  if version_ge "$GO_VERSION" "$GO_MIN_VERSION"; then
    ok "Go $GO_VERSION"
  else
    fail "Go $GO_VERSION — requires ${GO_MIN_VERSION}+"
    if $HAS_BREW && confirm "Install latest Go via brew?"; then
      brew install go && ok "Go installed" && CRITICAL=$((CRITICAL - 1))
    else
      hint "Install from https://go.dev/dl/"
    fi
  fi
else
  fail "Go not found"
  if $HAS_BREW && confirm "Install Go via brew?"; then
    brew install go && ok "Go installed" && CRITICAL=$((CRITICAL - 1))
  else
    hint "Install from https://go.dev/dl/"
  fi
fi

# ── Go version vs go.mod ────────────────────────────────────────────

if command -v go &>/dev/null && [ -f "$ROOT_DIR/go.mod" ]; then
  GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
  MOD_VERSION=$(grep '^go ' "$ROOT_DIR/go.mod" | awk '{print $2}')
  if [ -n "$MOD_VERSION" ]; then
    if version_ge "$GO_VERSION" "$MOD_VERSION"; then
      ok "Go $GO_VERSION ≥ go.mod $MOD_VERSION"
    else
      fail "Go $GO_VERSION < go.mod $MOD_VERSION" "go.mod requires Go $MOD_VERSION but you have $GO_VERSION"
      hint "Update Go or lower the go directive in go.mod"
    fi
  fi
fi

# ── golangci-lint ────────────────────────────────────────────────────

if command -v golangci-lint &>/dev/null; then
  LINT_VERSION=$(golangci-lint version --short 2>/dev/null || golangci-lint --version 2>/dev/null | head -1)
  ok "golangci-lint $LINT_VERSION"
else
  fail "golangci-lint" "Required for ./dev lint and ./dev check."
  if $HAS_BREW && confirm "Install golangci-lint via brew?"; then
    brew install golangci-lint && ok "golangci-lint installed" && CRITICAL=$((CRITICAL - 1))
  elif command -v go &>/dev/null && confirm "Install via go install?"; then
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && ok "golangci-lint installed" && CRITICAL=$((CRITICAL - 1))
  else
    hint "brew install golangci-lint"
  fi
fi

section "Project"

# ── Git hooks ────────────────────────────────────────────────────────

if [ -f "$ROOT_DIR/.git/hooks/pre-commit" ]; then
  ok "Git hooks"
else
  warn "Git hooks not installed" "Pre-commit runs gofmt + golangci-lint on staged files."
  if confirm "Install git hooks now?"; then
    bash "$ROOT_DIR/scripts/install-hooks.sh" && ok "Git hooks installed" && WARNINGS=$((WARNINGS - 1))
  else
    hint "./scripts/install-hooks.sh"
  fi
fi

# ── Go dependencies ─────────────────────────────────────────────────

if [ -f "$ROOT_DIR/go.mod" ]; then
  if (cd "$ROOT_DIR" && go list -m all &>/dev/null 2>&1); then
    ok "Go dependencies"
  else
    warn "Go dependencies not downloaded"
    if confirm "Download Go dependencies?"; then
      (cd "$ROOT_DIR" && go mod download) && ok "Dependencies downloaded" && WARNINGS=$((WARNINGS - 1))
    fi
  fi
fi

# ── Build check ──────────────────────────────────────────────────────

if command -v go &>/dev/null; then
  if (cd "$ROOT_DIR" && go build ./... 2>/dev/null); then
    ok "Build passes"
  else
    fail "Build fails" "Run: go build ./..."
  fi
fi

# ── Tests ────────────────────────────────────────────────────────────

if command -v go &>/dev/null; then
  if (cd "$ROOT_DIR" && go test ./... -count=1 -short 2>/dev/null); then
    ok "Tests pass"
  else
    warn "Some tests failing" "Run: go test ./... -v"
  fi
fi

section "Optional Tools"

# ── gotestsum (for better test output) ──────────────────────────────

TOOLS_BIN="$ROOT_DIR/.tools/bin"
GOTESTSUM_FOUND=false

if command -v gotestsum &>/dev/null; then
  GOTESTSUM_FOUND=true
  ok "gotestsum $(gotestsum --version 2>/dev/null | head -1)"
elif [ -x "$TOOLS_BIN/gotestsum" ]; then
  GOTESTSUM_FOUND=true
  ok "gotestsum (local .tools/bin)"
elif [ -x "$(go env GOPATH 2>/dev/null)/bin/gotestsum" ]; then
  GOTESTSUM_FOUND=true
  ok "gotestsum (GOPATH/bin)"
fi

if ! $GOTESTSUM_FOUND; then
  warn "gotestsum not found" "Optional — provides cleaner test output."
  if command -v go &>/dev/null && confirm "Install gotestsum via go install?"; then
    go install gotest.tools/gotestsum@latest && ok "gotestsum installed" && WARNINGS=$((WARNINGS - 1))
  else
    hint "go install gotest.tools/gotestsum@latest"
  fi
fi

# ── jq (for test summary parsing) ───────────────────────────────────

if command -v jq &>/dev/null; then
  ok "jq $(jq --version 2>/dev/null)"
else
  warn "jq not found" "Optional — needed for test summary when gotestsum unavailable."
  if $HAS_BREW && confirm "Install jq via brew?"; then
    brew install jq && ok "jq installed" && WARNINGS=$((WARNINGS - 1))
  else
    hint "brew install jq"
  fi
fi

# ── Docker (for E2E) ────────────────────────────────────────────────

if command -v docker &>/dev/null; then
  ok "Docker (for E2E tests)"
else
  warn "Docker not found" "Optional — needed for E2E tests."
  hint "Install from https://docker.com"
fi

# ── GoReleaser (for releases) ───────────────────────────────────────

if command -v goreleaser &>/dev/null; then
  ok "GoReleaser $(goreleaser --version 2>/dev/null | head -1 | awk '{print $NF}')"
else
  warn "GoReleaser not found" "Optional — needed for local release builds."
  hint "brew install goreleaser"
fi

# ── Summary ──────────────────────────────────────────────────────────

section "Summary"
echo ""

if [ $CRITICAL -eq 0 ] && [ $WARNINGS -eq 0 ]; then
  echo -e "  ${SUCCESS}${BOLD}All checks passed!${NC} You're ready to develop."
  echo ""
  echo -e "  ${MUTED}Next steps:${NC}"
  echo -e "    ${MUTED}./dev test          — run tests${NC}"
  echo -e "    ${MUTED}./dev check         — full check suite${NC}"
  echo -e "    ${MUTED}./dev build         — build CLI binary${NC}"
  exit 0
fi

[ $CRITICAL -gt 0 ] && echo -e "  ${ERROR}✗${NC} $CRITICAL critical issue(s) remaining"
[ $WARNINGS -gt 0 ] && echo -e "  ${ACCENT}·${NC} $WARNINGS warning(s)"

if [ $CRITICAL -gt 0 ]; then
  echo ""
  echo -e "  ${MUTED}After fixing, run ./dev doctor again.${NC}"
  exit 1
fi

exit 0
