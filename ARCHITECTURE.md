# Architecture — idpi-shield

## Design Philosophy

idpi-shield follows a **tiered defense** architecture that prioritizes speed and simplicity while enabling deep semantic analysis when needed.

**Core principle:** Add one library, get protection. Add the service for AI-grade protection.

---

## System Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                      YOUR APPLICATION                            │
│  (Go · Node.js/TypeScript · Rust · Python · any language)       │
│                                                                  │
│   ┌─────────────────────────────────────────┐                   │
│   │         idpi-shield CLIENT LIB          │ ◄── Tier 1        │
│   │  • Domain allowlist check               │                   │
│   │  • Unicode normalization                │                   │
│   │  • Pattern matching (88 patterns)       │                   │
│   │  • Risk scoring (0–100)                 │                   │
│   │  • Multi-language (EN/FR/ES/DE/JA)      │                   │
│   │  • Sub-millisecond response             │                   │
│   │  • Bounded decoding + input limits      │                   │
│   └───────────────┬─────────────────────────┘                   │
│                   │ (optional, score ≥ 60)                      │
│                   ▼                                              │
│   ┌─────────────────────────────────────────┐                   │
│   │         idpi-shield SERVICE             │ ◄── Tier 2        │
│   │  (Python microservice, runs separately) │                   │
│   │  • Semantic similarity detection        │                   │
│   │  • LLM-based intent analysis            │                   │
│   │  • REST API on localhost:7432           │                   │
│   └─────────────────────────────────────────┘                   │
└──────────────────────────────────────────────────────────────────┘
```

## Analysis Pipeline

```
Input Text
    │
       ├── [Mode: Fast] ───────────────────────────┐
    │                                            │
       ├── [Mode: Balanced/Deep]                    │
    │       │                                    │
    │       ▼                                    │
    │   ┌──────────┐                            │
    │   │Normalizer│                            │
    │   │• Strip zero-width chars               │
    │   │• Map homoglyphs (Cyrillic→Latin)      │
    │   │• Full-width → ASCII                   │
    │   │• Collapse whitespace                  │
    │   └────┬─────┘                            │
    │        │                                   │
    ▼        ▼                                   │
┌──────────────┐                                │
│   Scanner    │ ◄──────────────────────────────┘
│• 88 compiled regex patterns                   │
│• 7 threat categories                          │
│• 5 languages                                  │
└──────┬───────┘                                │
       │ matches[]                              │
       ▼                                        │
┌──────────────┐                                │
│   Scorer     │                                │
│• Category-weighted scoring                    │
│• Cross-category amplification                 │
│• Attack chain combo bonuses                   │
│• Score clamped [0, 100]                       │
└──────┬───────┘                                │
       │ RiskResult (local)                     │
       │                                        │
       ├── [score < 60 OR mode ≠ deep] ───► Return local result
       │
       ├── [score ≥ 60 AND mode = deep AND service configured]
       │       │
       │       ▼
       │   ┌──────────────┐
       │   │Service Client│
       │   │POST /assess  │
       │   └──────┬───────┘
       │          │
       │     ┌────┴────┐
       │     │ success? │
       │     ├─ yes ──► Return service result
       │     └─ no  ──► Retry transient failures, then return local result
```

## Scoring Algorithm

### Severity Weights

| Severity | Weight | Meaning |
|----------|--------|---------|
| 1 | 10 | Weak signal, likely benign |
| 2 | 15 | Mild signal |
| 3 | 25 | Suspicious |
| 4 | 35 | Very likely attack |
| 5 | 45 | Almost certain attack |

### Score Computation

1. **Category grouping**: For each category, take the highest severity match as the primary weight.
2. **Diminishing returns**: Additional matches in the same category add `weight / 5` each (max 3 extra).
3. **Cross-category bonus**: `+15` per additional category beyond the first.
4. **Attack chain bonuses**:
   - instruction-override + exfiltration: `+20`
   - jailbreak + instruction-override: `+15`
   - role-hijack + exfiltration: `+15`
5. **Clamp** to `[0, 100]`.

### Score → Level Mapping

| Range | Level |
|-------|-------|
| 0–19 | safe |
| 20–39 | low |
| 40–59 | medium |
| 60–79 | high |
| 80–100 | critical |

### Blocking Thresholds

| Mode | Threshold |
|------|-----------|
| Normal | score ≥ 60 |
| Strict | score ≥ 40 |

## Normalization Strategy

The normalizer defeats common obfuscation techniques used in prompt injection attacks:

1. **Invisible character stripping**: Removes 20+ zero-width and invisible Unicode characters (U+200B, U+200C, U+200D, U+FEFF, etc.) that attackers insert between letters to break pattern matching.

2. **Homoglyph mapping**: Maps 50+ visually similar characters from Cyrillic, Greek, and mathematical symbol ranges to their ASCII equivalents. Example: Cyrillic 'а' (U+0430) → Latin 'a'.

3. **Full-width normalization**: Converts full-width ASCII variants (U+FF01–U+FF5E) to standard ASCII (U+0021–U+007E).

4. **Whitespace collapsing**: Multiple whitespace characters (spaces, tabs, newlines) are collapsed to a single space.

## Thread Safety

All components are safe for concurrent use:
- **Scanner**: Read-only after construction (compiled regex patterns).
- **Normalizer**: Stateless — pure function.
- **Domain checker**: Read-only after construction.
- **Service client**: Uses `http.Client` which is concurrency-safe.
- **Client**: Composes all of the above — no mutable state during operation.

## Runtime Guardrails

The current implementation includes lightweight production guardrails:

1. **Input bounding**: `MaxInputBytes` limits analysis payload size.
2. **Decode bounding**: `MaxDecodeDepth` and `MaxDecodedVariants` cap obfuscation expansion.
3. **Retry controls**: `ServiceRetries` retries transient deep-service failures.
4. **Circuit breaker**: `ServiceCircuitFailureThreshold` + `ServiceCircuitCooldown` prevent repeated service stalls from impacting local scans.
5. **MCP HTTP auth**: Optional bearer/API-key auth (`--auth-token`) for streamable HTTP transport.

## Dependencies

The root library primarily uses Go standard library components plus targeted external packages where needed (for example Unicode normalization). CLI/MCP adapter components have additional dependencies.
