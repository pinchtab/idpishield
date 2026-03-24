// Package idpishield provides defense against Indirect Prompt Injection (IDPI) attacks.
//
// It analyzes text content for hidden instructions that could hijack AI agent behavior
// when processing untrusted web content. The library operates in tiers:
//
//   - Tier 1 (library only): Fast local pattern matching with zero infrastructure.
//   - Tier 2 (library + service): Adds semantic analysis via the idpi-shield Python service.
//
// Basic usage:
//
//	client := idpishield.New(idpishield.Config{
//	    Mode: idpishield.ModeBalanced,
//	})
//	result := client.Scan(webPageContent)
//	if result.Blocked {
//	    log.Printf("Blocked: %s (score: %d)", result.Reason, result.Score)
//	}
package idpishield

import (
	"context"
	"time"

	"github.com/pinchtab/idpi-shield/internal/engine"
)

// Mode configures analysis depth.
type Mode = engine.Mode

const (
	// ModeFast performs pattern matching only against raw input.
	ModeFast = engine.ModeFast

	// ModeBalanced applies normalization/preprocessing before pattern matching.
	ModeBalanced = engine.ModeBalanced

	// ModeDeep includes balanced analysis plus optional service escalation.
	ModeDeep = engine.ModeDeep
)

// RiskResult is the canonical return type for all idpi-shield analysis operations.
// Every client library and the service returns this exact structure.
type RiskResult = engine.RiskResult

// Config controls the behavior of a Shield instance.
type Config struct {
	// Mode controls analysis depth: fast, balanced (default), or deep.
	Mode Mode

	// AllowedDomains is a list of trusted domain patterns for CheckDomain.
	// If non-empty, domains not matching any pattern are considered threats.
	// Supports wildcards: "*.example.com" matches "sub.example.com".
	AllowedDomains []string

	// StrictMode lowers blocking thresholds (score >= 40 blocks instead of >= 60).
	StrictMode bool

	// ServiceURL is the URL of the idpi-shield analysis service.
	// Only used in deep mode. Example: "http://localhost:7432"
	ServiceURL string

	// ServiceTimeout is the timeout for HTTP requests to the service.
	// Defaults to 5 seconds if zero.
	ServiceTimeout time.Duration

	// ServiceRetries controls retry attempts for transient deep-service failures.
	// Retries are disabled when set to 0.
	ServiceRetries int

	// ServiceCircuitFailureThreshold opens a temporary circuit after this many
	// consecutive transient deep-service failures. 0 disables circuit breaking.
	ServiceCircuitFailureThreshold int

	// ServiceCircuitCooldown is the duration the deep-service circuit stays open
	// after the failure threshold is reached.
	ServiceCircuitCooldown time.Duration

	// MaxInputBytes caps the amount of text analyzed per request.
	// If <= 0, the default behavior is to analyze the full input.
	MaxInputBytes int

	// MaxDecodeDepth bounds recursive decoding attempts (Base64/HEX/etc.).
	// If <= 0, a safe default depth is used.
	MaxDecodeDepth int

	// MaxDecodedVariants bounds how many decoded variants are scanned.
	// If <= 0, a safe default limit is used.
	MaxDecodedVariants int
}

// Shield is the main entry point for idpi-shield analysis.
// Safe for concurrent use by multiple goroutines.
type Shield struct {
	engine *engine.Engine
}

// New creates a new Shield with the given configuration.
func New(cfg Config) *Shield {
	return &Shield{
		engine: engine.New(toEngineCfg(cfg)),
	}
}

// Assess analyzes text for indirect prompt injection threats.
// Returns a RiskResult with score, severity level, and matched patterns.
func (s *Shield) Assess(text, url string) RiskResult {
	return s.engine.Assess(text, url)
}

// AssessContext is like Assess but accepts a context for service call cancellation.
func (s *Shield) AssessContext(ctx context.Context, text, sourceURL string) RiskResult {
	return s.engine.AssessContext(ctx, text, sourceURL)
}

// CheckDomain evaluates whether a URL's domain is in the configured allowlist.
// Returns a RiskResult indicating whether the domain is trusted.
// If no allowlist is configured, always returns safe.
func (s *Shield) CheckDomain(rawURL string) RiskResult {
	return s.engine.CheckDomain(rawURL)
}

// Wrap encloses untrusted web content with trust boundary markers.
// This helps LLMs distinguish between trusted system instructions and
// untrusted external content that should be treated as data only.
func (s *Shield) Wrap(content, sourceURL string) string {
	return s.engine.Wrap(content, sourceURL)
}

// Scan is a compatibility alias for Assess.
func (s *Shield) Scan(text string) RiskResult {
	return s.Assess(text, "")
}

// ScanContext is a compatibility alias for AssessContext.
func (s *Shield) ScanContext(ctx context.Context, text string) RiskResult {
	return s.AssessContext(ctx, text, "")
}

// ParseMode converts a string to a Mode value.
// Returns ModeBalanced for unrecognized values.
func ParseMode(s string) Mode {
	return engine.ParseMode(s)
}

// ParseModeStrict converts a string to a Mode value and returns an error for unsupported values.
// Empty input defaults to ModeBalanced.
func ParseModeStrict(s string) (Mode, error) {
	return engine.ParseModeStrict(s)
}

// ScoreToLevel maps a 0–100 score to its corresponding severity level.
func ScoreToLevel(score int) string {
	return engine.ScoreToLevel(score)
}

// AssessWithMode selects a Shield instance by mode and runs Assess.
// If mode is empty, defaultMode is used.
func AssessWithMode(shields map[Mode]*Shield, defaultMode Mode, text, mode string) (RiskResult, error) {
	engines := make(map[Mode]*engine.Engine, len(shields))
	for m, s := range shields {
		engines[m] = s.engine
	}
	return engine.AssessWithMode(engines, defaultMode, text, mode)
}

func toEngineCfg(cfg Config) engine.Config {
	return engine.Config{
		Mode:                           cfg.Mode,
		AllowedDomains:                 cfg.AllowedDomains,
		StrictMode:                     cfg.StrictMode,
		ServiceURL:                     cfg.ServiceURL,
		ServiceTimeout:                 cfg.ServiceTimeout,
		ServiceRetries:                 cfg.ServiceRetries,
		ServiceCircuitFailureThreshold: cfg.ServiceCircuitFailureThreshold,
		ServiceCircuitCooldown:         cfg.ServiceCircuitCooldown,
		MaxInputBytes:                  cfg.MaxInputBytes,
		MaxDecodeDepth:                 cfg.MaxDecodeDepth,
		MaxDecodedVariants:             cfg.MaxDecodedVariants,
	}
}
