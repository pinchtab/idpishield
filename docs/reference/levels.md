# Levels — Tier 1 vs Tier 2 Behavior Specification

**Version:** 1.0.0

---

## Tier Overview

| Tier | Components | Infrastructure | Latency |
|------|-----------|---------------|---------|
| **Tier 1** | Client library only | None | Sub-millisecond |
| **Tier 2** | Client library + Python service | Python runtime, optional LLM | 50–200ms |

## Modes

Every client library supports three modes that control analysis depth.

### `light`

- **Pattern matching only** against raw input text.
- No Unicode normalization.
- No domain checking.
- No service escalation.
- Fastest mode: < 0.1ms typical.
- Use case: high-throughput pipelines where speed is critical.

### `balanced` (default)

- Unicode normalization applied before pattern matching.
- Domain allowlist checked (if configured).
- No service escalation.
- Typical latency: < 1ms.
- Use case: general-purpose protection with good accuracy.

### `smart`

- All `balanced` analysis performed first.
- If local score ≥ 60 AND `ServiceURL` is configured, escalates to the Python service.
- Service performs semantic similarity analysis and optional LLM-based intent detection.
- Service may upgrade or downgrade the local score.
- If service is unreachable, falls back to local result gracefully (no crash, no error propagation).
- Typical latency: 1–5ms locally, 50–200ms with service round-trip.
- Use case: maximum protection for sensitive AI pipelines.

## Escalation Flow (Smart Mode)

```
Input text
    │
    ▼
[Normalize] → [Pattern Match] → [Score]
    │                                │
    │                          score < 60?
    │                           ╱        ╲
    │                         yes         no
    │                          │           │
    │                   Return local   [Service /assess]
    │                     result            │
    │                                  success?
    │                                 ╱        ╲
    │                               yes         no
    │                                │           │
    │                          Return service  Return local
    │                            result        result (fallback)
```

## Fallback Guarantees

1. If `ServiceURL` is empty, smart mode behaves identically to balanced mode.
2. If the service is unreachable (network error, timeout, non-200 status), the client MUST return the local result. It MUST NOT return an error or panic.
3. The `source` field in RiskResult indicates whether the final result came from `"local"` or `"service"` analysis.
4. Service timeout defaults to 5 seconds and is configurable.

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | `string` | `"balanced"` | Analysis mode: `"light"`, `"balanced"`, or `"smart"`. |
| `allowedDomains` | `[]string` | `[]` | Domain allowlist patterns. Empty = allow all. |
| `strictMode` | `bool` | `false` | Lower blocking thresholds for maximum protection. |
| `serviceURL` | `string` | `""` | Tier 2 service URL. Only used in `smart` mode. |
| `serviceTimeout` | `duration` | `5s` | Timeout for service HTTP requests. |
