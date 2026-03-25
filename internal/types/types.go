// Package types defines the shared type definitions for idpishield.
// Both the public API (root package) and internal engine import from here.
package types

import (
	"fmt"
	"strings"
)

// Mode configures analysis depth.
type Mode string

const (
	// ModeFast performs pattern matching only against raw input.
	ModeFast Mode = "fast"

	// ModeBalanced applies normalization/preprocessing before pattern matching.
	ModeBalanced Mode = "balanced"

	// ModeDeep includes balanced analysis plus optional service escalation.
	ModeDeep Mode = "deep"
)

// String returns the string representation of Mode.
func (m Mode) String() string {
	if m == "" {
		return string(ModeBalanced)
	}
	return string(m)
}

// ParseMode converts a string to a Mode value.
// Returns ModeBalanced for unrecognized values.
func ParseMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "fast":
		return ModeFast
	case "balanced":
		return ModeBalanced
	case "deep":
		return ModeDeep
	default:
		return ModeBalanced
	}
}

// ParseModeStrict converts a string to a Mode value and returns an error for unsupported values.
// Empty input defaults to ModeBalanced.
func ParseModeStrict(s string) (Mode, error) {
	raw := strings.ToLower(strings.TrimSpace(s))
	if raw == "" {
		return ModeBalanced, nil
	}

	switch raw {
	case "fast":
		return ModeFast, nil
	case "balanced":
		return ModeBalanced, nil
	case "deep":
		return ModeDeep, nil
	default:
		return "", fmt.Errorf("invalid mode %q: expected fast, balanced, or deep", s)
	}
}

// Intent classifies the attacker's goal based on detected patterns.
// Derived from the Unit 42 IDPI taxonomy (March 2026).
type Intent string

const (
	IntentNone              Intent = ""
	IntentInstructionBypass Intent = "instruction-bypass"
	IntentDataExfiltration  Intent = "data-exfiltration"
	IntentDataDestruction   Intent = "data-destruction"
	IntentUnauthorizedTx    Intent = "unauthorized-transaction"
	IntentJailbreak         Intent = "jailbreak"
	IntentOutputSteering    Intent = "output-steering"
	IntentSystemCompromise  Intent = "system-compromise"
	IntentResourceExhaust   Intent = "resource-exhaustion"
)

// RiskResult is the canonical return type for all idpishield analysis operations.
// Every client library and the service returns this exact structure.
type RiskResult struct {
	// Score is the risk score from 0 (clean) to 100 (confirmed attack).
	Score int `json:"score"`

	// Level is the severity label derived from Score.
	Level string `json:"level"`

	// Blocked indicates whether the content was blocked based on the current configuration.
	Blocked bool `json:"blocked"`

	// Reason is a human-readable explanation of the analysis result.
	Reason string `json:"reason"`

	// Patterns lists the IDs of patterns that matched.
	Patterns []string `json:"patterns"`

	// Categories lists the unique threat categories detected.
	Categories []string `json:"categories"`

	// Intent classifies the primary attacker goal. Empty when no threat is detected.
	Intent Intent `json:"intent,omitempty"`
}

// ScoreToLevel maps a 0–100 score to its corresponding severity level.
func ScoreToLevel(score int) string {
	switch {
	case score < 20:
		return "safe"
	case score < 40:
		return "low"
	case score < 60:
		return "medium"
	case score < 80:
		return "high"
	default:
		return "critical"
	}
}

// ShouldBlock determines whether content should be blocked given a score and config.
func ShouldBlock(score int, strict bool) bool {
	if strict {
		return score >= 40
	}
	return score >= 60
}

// SafeResult returns a clean RiskResult with no threats detected.
func SafeResult() RiskResult {
	return RiskResult{
		Score:      0,
		Level:      "safe",
		Blocked:    false,
		Reason:     "No threats detected",
		Patterns:   []string{},
		Categories: []string{},
	}
}
