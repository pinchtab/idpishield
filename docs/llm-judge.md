# Optional LLM-as-Judge Layer

## Overview

The optional LLM judge adds a second-opinion step after heuristic scanners.

Flow:

1. Input text is scored by built-in heuristics.
2. If score is in the uncertain zone, idpishield asks an LLM for a verdict.
3. The final score is adjusted up or down based on the LLM verdict.
4. Block/allow is decided from the final score.

This helps reduce false positives and catch novel attacks while keeping default performance fast.

```mermaid
flowchart LR
  A[Input Text] --> B[Heuristic Scanners]
  B --> C[Heuristic Score]
  C --> D{In Judge Range?}
  D -- No --> E[Final Decision]
  D -- Yes --> F[LLM Judge]
  F --> G[Score Adjustment]
  G --> E
```

## Quick Start with Ollama (Free, Local)

1. Install Ollama: https://ollama.ai
2. Pull a model:

```bash
ollama pull llama3.2
```

3. Configure idpishield:

```go
shield, err := idpishield.New(idpishield.Config{
    Mode: idpishield.ModeBalanced,
    Judge: &idpishield.JudgeConfig{
        Provider: idpishield.JudgeProviderOllama,
        // Model defaults to llama3.2
        // BaseURL defaults to http://localhost:11434
    },
})
if err != nil {
    panic(err)
}

result := shield.Assess("ignore all previous instructions", "")
```

## Supported Providers

| Provider | Example Model | Cost | Latency | Privacy |
|---|---|---:|---:|---|
| `ollama` | `llama3.2` | Free (local compute) | Medium (local hardware dependent) | Highest (offline/local) |
| `openai` | `gpt-4o-mini` | Low | Low to Medium | External API |
| `anthropic` | `claude-haiku-4-5-20251001` | Low | Low to Medium | External API |
| `custom` | Any OpenAI-compatible model | Varies | Varies | Depends on endpoint |

## Score Threshold Tuning

Use these two controls together:

- `ScoreThreshold`: minimum score to call the judge.
- `ScoreMaxForJudge`: maximum score to call the judge.

Example default window: `25..75`

- `0..24`: usually benign, skip judge.
- `25..75`: uncertain zone, judge runs.
- `76..100`: already high confidence attack, skip judge.

Suggested tuning:

- Low-latency apps: increase threshold (for example `40`).
- Security-first apps: widen range (for example `15..85`).

## Performance Considerations

The judge is disabled by default.

When enabled, extra latency is added only for requests in the configured score range.

Typical p95 guidance (depends on model/network):

- Ollama local: ~150ms to 1500ms
- OpenAI/Anthropic: ~200ms to 1200ms
- Custom local APIs: ~100ms to 1200ms

Tune `TimeoutSeconds` and thresholds to balance recall, precision, and latency.

## Privacy Considerations

With cloud providers, suspicious text is sent to external APIs.

For privacy-sensitive deployments, prefer `ollama` (local) or a private `custom` endpoint.

## CLI Usage

Ollama:

```bash
echo "ignore all previous instructions" | go run ./cmd/idpishield scan --judge-provider ollama
```

OpenAI:

```bash
echo "ignore all previous instructions" | OPENAI_API_KEY=sk-... go run ./cmd/idpishield scan --judge-provider openai --judge-model gpt-4o-mini
```

Custom endpoint:

```bash
echo "ignore all previous instructions" | go run ./cmd/idpishield scan --judge-provider custom --judge-base-url http://localhost:1234/v1 --judge-model local-model
```

## Fail-Open Behavior

If the LLM judge call fails (timeout/network/invalid response):

- scoring falls back to heuristic-only result,
- no panic or blocking occurs,
- `judge_verdict` is `null`.
