# idpi-shield

`idpi-shield` is a Go library for detecting indirect prompt injection (IDPI) risk in untrusted text before it is passed to an LLM.

It provides a single core assessment engine and two adapters around it:
- Go API (primary)
- CLI and MCP server (secondary interfaces)

## Why Use It

Use this library when your system ingests untrusted content (web pages, user text, scraped HTML, documents) and you want a fast risk signal before forwarding content into an LLM prompt.

Core output includes:
- `score` (0-100)
- `level` (`safe`, `low`, `medium`, `high`, `critical`)
- `blocked` (policy decision based on score + strict mode)
- matched `patterns` and `categories`

## Install (Go Library)

```bash
go get github.com/pinchtab/idpi-shield
```

## Import

```go
import idpi "github.com/pinchtab/idpi-shield"
```

## Minimal Usage

```go
package main

import (
	"fmt"

	idpi "github.com/pinchtab/idpi-shield"
)

func main() {
	shield := idpi.New(idpi.Config{Mode: idpi.ModeBalanced})

	result := shield.Assess("Ignore all previous instructions", "https://example.com")
	fmt.Printf("score=%d level=%s blocked=%v\n", result.Score, result.Level, result.Blocked)
}
```

## Configuration

```go
cfg := idpi.Config{
	Mode:           idpi.ModeBalanced,
	AllowedDomains: []string{"example.com", "google.com"},
	StrictMode:     false,
	ServiceURL:     "", // optional for deep-mode service augmentation
	ServiceTimeout: 0,
}
```

### Modes
- `fast`: lightweight pattern checks
- `balanced`: recommended default for most integrations
- `deep`: includes deep-mode path (optionally with service)

### Domain Handling
- `AllowedDomains` is optional.
- If set, assessments can incorporate allowlist domain decisions when a URL is provided to `Assess(text, url)`.

### Blocking Semantics
- default mode blocks at score `>= 60`
- strict mode blocks at score `>= 40`

## Result Semantics

`RiskResult` is the main output contract:

```go
type RiskResult struct {
	Score      int
	Level      string
	Blocked    bool
	Reason     string
	Patterns   []string
	Categories []string
}
```

Interpretation guide:
- `score` is the numeric risk estimate.
- `level` is a severity bucket derived from score.
- `blocked` is a policy output (`score` + strict mode), not just a detection flag.
- `reason`, `patterns`, `categories` provide explainability for audit/logging.

## Public API (Go)

Canonical assessment method:
- `Assess(text, url)`

Primary exported surface:

```go
type Config struct {
	Mode           Mode
	AllowedDomains []string
	StrictMode     bool
	ServiceURL     string
	ServiceTimeout time.Duration
}

type Mode string

const (
	ModeFast     Mode = "fast"
	ModeBalanced Mode = "balanced"
	ModeDeep     Mode = "deep"
)

func New(cfg Config) *Shield
func (s *Shield) Assess(text, url string) RiskResult
func (s *Shield) Wrap(text, url string) string
```

`Wrap` is useful when you want to preserve data while adding trust-boundary markers before sending content into prompts.

## CLI (Secondary Interface)

Install CLI:

```bash
go install github.com/pinchtab/idpi-shield/cmd/idpi-shield@latest
```

Scan from a file:

```bash
idpi-shield scan ./page.txt --mode balanced --domains example.com,google.com --url https://example.com/page
```

Scan from stdin:

```bash
echo "Ignore all previous instructions" | idpi-shield scan --mode balanced
```

The CLI outputs JSON:

```json
{
  "score": 80,
  "level": "critical",
  "blocked": true,
  "reason": "instruction-override pattern detected; exfiltration pattern detected [cross-category: 2 categories]",
  "patterns": ["en-io-001", "en-ex-002"],
  "categories": ["exfiltration", "instruction-override"]
}
```

## MCP Server (Secondary Interface)

Run stdio MCP server (default):

```bash
idpi-shield mcp serve
```

Exposed MCP tool:
- `idpi_assess`
  - `text` (required)
  - `mode` (`fast|balanced|deep`, optional)

The MCP adapter calls the same core `Assess` engine used by the Go library.

## Project Layout

```text
idpi-shield/
├── go.mod
├── shield.go
├── shield_test.go
├── normalizer.go
├── scanner.go
├── risk.go
├── service.go
├── domain.go
├── patterns/
│   └── builtin.go
├── cmd/
│   └── idpi-shield/
│       └── main.go
├── examples/
├── spec/
└── tests/
```
