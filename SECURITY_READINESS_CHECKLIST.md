# Security Readiness Checklist

Use this checklist before releasing to production.

## Core Quality Gates

- [ ] `go test ./...` passes in root module.
- [ ] `go vet ./...` passes.
- [ ] Black-box integration tests pass in `tests/integration`.
- [ ] Benchmark run completed and stored in `benchmark/reports/`.

## Detection And Safety Gates

- [ ] Known obfuscation vectors are detected (base64, hex, unicode, zero-width).
- [ ] Benign documentation/code examples do not trigger high/critical by default.
- [ ] Domain allowlist behavior verified for allowed and disallowed URLs.
- [ ] Deep mode fallback behavior validated when external service is unavailable.

## Runtime Guardrail Gates

- [ ] `MaxInputBytes` set for production profile.
- [ ] `MaxDecodeDepth` and `MaxDecodedVariants` set for production profile.
- [ ] `ServiceRetries` configured (non-zero for production deep mode).
- [ ] `ServiceCircuitFailureThreshold` and `ServiceCircuitCooldown` configured.

## MCP Transport Gates

- [ ] HTTP MCP transport enabled only with `--auth-token`.
- [ ] Reverse proxy/TLS configured in production deployment.
- [ ] Token rotation process documented.

## Operational Gates

- [ ] Error logs do not leak sensitive content.
- [ ] Incident runbook available for service outage and false-positive spikes.
- [ ] Rollback plan documented.
- [ ] Release notes include behavioral changes and migration notes.
