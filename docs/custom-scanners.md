# Custom / Pluggable Scanners

## Overview
Custom scanners let you add domain-specific detection logic without forking idpishield. Built-in scanners always run first, and your scanners run after them.

## The Scanner Interface
```go
type Scanner interface {
    Name() string
    Scan(ctx ScanContext) ScanResult
}
```

## ScanContext Fields
| Field | Type | Description |
| --- | --- | --- |
| `Text` | `string` | Normalized text after decoding/normalization. |
| `RawText` | `string` | Original text before normalization. |
| `URL` | `string` | Source URL when available. |
| `Mode` | `idpishield.Mode` | Current scan mode (`fast`, `balanced`, `deep`, `strict`). |
| `IsOutputScan` | `bool` | True when called from `AssessOutput()`. |
| `CurrentScore` | `int` | Score accumulated by built-ins before your scanner runs. |

## ScanResult Fields
| Field | Type | Description |
| --- | --- | --- |
| `Score` | `int` | Contribution from this scanner (0..100 before caps). |
| `Category` | `string` | Category label (lowercase hyphenated). |
| `Reason` | `string` | Human-readable reason. |
| `Matched` | `bool` | True if this scanner detected a hit. |
| `PatternID` | `string` | Optional pattern ID for audit trails. |
| `Metadata` | `map[string]string` | Optional metadata for debugging. |

`ScanContext.Mode` controls analysis pipeline depth (including `strict` full-pipeline execution).
This is different from `Config.StrictMode`, which only changes blocking thresholds.

## Writing Your First Scanner
1. Define a scanner struct that implements `Name()` and `Scan()`.
2. In `Scan()`, inspect `ctx.Text` using helper utilities.
3. Return `ScanResult{}` when no match.
4. Register it in `Config.ExtraScanners`.

Keyword scanner example:
```go
type KeywordScanner struct {
    Name_ string
    Keywords []string
}

func (s *KeywordScanner) Name() string { return s.Name_ }

func (s *KeywordScanner) Scan(ctx idpishield.ScanContext) idpishield.ScanResult {
    h := idpishield.Helpers()
    for _, kw := range s.Keywords {
        if h.ContainsWholeWord(ctx.Text, kw) {
            return idpishield.ScanResult{
                Score: 15,
                Category: "keyword-policy",
                Reason: "keyword detected: " + kw,
                Matched: true,
            }
        }
    }
    return idpishield.ScanResult{}
}
```

## Best Practices
- Pre-compile regexes in constructors, not inside `Scan()`.
- Keep `Scan()` fast because it runs for every assessment.
- Use `ctx.CurrentScore` for context-aware scoring.
- Return `ScanResult{}` when there is no match.
- Keep `Scan()` goroutine-safe by avoiding shared mutable state.
- Never panic in `Scan()`; idpishield recovers panics, but returning safely is better.

## Available Helpers
- `idpishield.Helpers().ContainsAny(text, phrases)`
- `idpishield.Helpers().ContainsAll(text, phrases)`
- `idpishield.Helpers().WordCount(text)`
- `idpishield.Helpers().ContainsWholeWord(text, word)`
- `idpishield.Helpers().CountOccurrences(text, phrase)`

Example:
```go
h := idpishield.Helpers()
if h.ContainsAny(ctx.Text, []string{"transfer", "wire"}) {
    // ...
}
```

## Score Caps
`Config.MaxCustomScannerScore` limits how much any single custom scanner can contribute. Default: `50`. Global score remains capped at `100`.

## Reserved Scanner Names
You cannot use these scanner names:
- `secrets`
- `gibberish`
- `toxicity`
- `emotional-manipulation`
- `ban-substring`
- `ban-topic`
- `ban-competitor`
- `custom-regex`
- `system-prompt-leak`
- `malicious-url`
- `pii-leak`
- `harmful-code`
- `relevance-drift`
- `output-gibberish`

## Input vs Output Scanners
- Use `ExtraScanners` to run custom logic on `Assess()` / `AssessContext()`.
- Use `ExtraOutputScanners` to run custom logic on `AssessOutput()` only.

## Ergonomic Registration API
You can keep using `Config.ExtraScanners`, or register scanners ergonomically and select them by name:

```go
shield, err := idpishield.New(idpishield.Config{Mode: idpishield.ModeBalanced})
if err != nil {
    panic(err)
}

shield.RegisterScanner(NewInvisibleTextScanner())
shield.RegisterScanner(NewSecretsScanner())

// Unknown names are ignored. Built-in scanners always run.
shield.WithScanners("idpi", "secrets")
```

## Production Example
See the full runnable example in `examples/custom-scanner/main.go`.
