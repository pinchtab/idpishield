## Title

Security Hardening + Runtime Guardrails + Documentation Refresh

## Summary

This PR continues the next hardening phase with production-safe controls while keeping the default runtime lightweight.

### What changed

- Added MCP HTTP auth guard (`--auth-token`) with Bearer and `X-API-Key` support.
- Added deep-service resilience controls:
  - `ServiceRetries`
  - circuit breaker via `ServiceCircuitFailureThreshold` and `ServiceCircuitCooldown`
- Added runtime profile support (`--profile default|production`) for scan and MCP commands.
- Added production profile defaults for strict mode and bounded analysis limits.
- Added black-box integration test module under `tests/integration`.
- Updated docs (`README.md`, `ARCHITECTURE.md`, `spec/API.md`) and added `SECURITY_READINESS_CHECKLIST.md`.

## Why

Main risk gaps addressed:

- Unauthenticated MCP HTTP transport exposure.
- Repeated deep-service failures causing degraded behavior.
- Unbounded/overly permissive runtime settings in production.
- Documentation drift against current behavior and flags.

## Key Details

### Security

- MCP HTTP auth middleware rejects unauthorized calls with `401`.
- Constant-time token comparison is used for token checks.

### Resilience

- Transient service failures are retried with bounded exponential backoff.
- Circuit breaker opens after configurable consecutive transient failures.
- Local detection remains available when deep service fails.

### Runtime Profiles

Production profile sets safer defaults when unset:

- strict mode enabled
- bounded input and decode fan-out
- deep-service retry + circuit defaults

## Test Plan

### Root module

- `go test ./...`
- `go vet ./...`

### Integration module

- `cd tests/integration`
- `go mod tidy`
- `go test ./...`

### Black-box scenarios covered

- obfuscated attacks (base64/zero-width/homoglyph/entity)
- benign documentation and code-like content
- combined domain + text signal behavior
- deep mode service outage fallback
- high-concurrency stability
- bounded-input tail attack detection

## Breaking changes

None. New controls are additive and default-safe.

## Rollout notes

- For MCP HTTP, set `--auth-token` and deploy behind TLS.
- For production, prefer `--profile production`.
- Review `SECURITY_READINESS_CHECKLIST.md` before release.
