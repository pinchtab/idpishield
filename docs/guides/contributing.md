# Contributing to idpi-shield

## Quick Start

```bash
git clone https://github.com/pinchtab/idpishield.git
cd idpishield
./dev doctor    # checks environment, offers to install missing tools
./dev check     # runs all checks (format + vet + lint + tests)
```

## Development Commands

```bash
./dev test          # run unit tests
./dev test race     # with race detector
./dev coverage      # coverage report
./dev lint          # golangci-lint
./dev fmt           # format code
./dev build         # build CLI binary
./dev benchmark     # run benchmarks
```

## Project Structure

```
idpishield.go              Public API (thin wrapper)
internal/engine/           Implementation (scanner, normalizer, decoders, etc.)
patterns/                  Detection patterns (public — consumers can inspect)
cmd/idpi-shield/           CLI entry point
benchmark/                 Benchmark suite
docs/                      Documentation
tests/                     Integration & compliance tests
```

## Code Standards

- `gofmt` enforced via pre-commit hook
- golangci-lint with strict linter set (`.golangci.yml`)
- Tests next to code (`*_test.go` in same package)
- Race detector in CI (`-race` flag)
- `internal/` for all implementation details — public API is the root package

## Git Hooks

Install pre-commit hooks (runs gofmt + lint on staged files):

```bash
./scripts/install-hooks.sh
```

Or run `./dev doctor` which will offer to install them.

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Run `./dev check` — all checks must pass
3. Write tests for new functionality
4. Keep PRs focused — one feature or fix per PR
5. Update docs if behavior changes

## Reporting Issues

Open an issue on GitHub with:
- What you expected vs what happened
- Minimal reproduction case
- Go version and OS
