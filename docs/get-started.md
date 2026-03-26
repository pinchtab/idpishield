# Get Started

## As a Go Library

```bash
go get github.com/pinchtab/idpishield
```

```go
package main

import (
    "fmt"
    idpi "github.com/pinchtab/idpishield"
)

func main() {
    shield := idpi.New(idpi.Config{
        Mode: idpi.ModeBalanced,
    })

    result := shield.Assess("Ignore all previous instructions", "")
    fmt.Printf("Score: %d, Level: %s, Blocked: %v\n", result.Score, result.Level, result.Blocked)
}
```

## As a CLI

```bash
go install github.com/pinchtab/idpishield/cmd/idpishield@latest
```

```bash
# Scan a file
idpishield scan input.txt

# Scan from stdin
echo "Ignore previous instructions" | idpishield scan -

# With domain allowlist
idpishield scan page.html --domains example.com,google.com --url https://example.com

# MCP server mode
idpishield mcp serve
```

## Analysis Modes

| Mode | What it does | When to use |
|------|-------------|-------------|
| `fast` | Pattern matching on raw input | High-throughput, low-latency |
| `balanced` | Normalization + pattern matching | Default — best tradeoff |
| `deep` | Balanced + optional service escalation | Maximum detection accuracy |

## Configuration

```go
shield := idpi.New(idpi.Config{
    Mode:           idpi.ModeBalanced,
    AllowedDomains: []string{"example.com", "*.trusted.org"},
    StrictMode:     true,  // block at score >= 40 instead of >= 60
    MaxInputBytes:  50000, // cap analysis input
})
```

## Next Steps

- [Architecture](architecture/design.md) — how the tiered defense works
- [Risk Result](reference/risk-result.md) — understanding scores and levels
- [Patterns](reference/patterns.md) — what gets detected
- [Contributing](guides/contributing.md) — how to contribute
