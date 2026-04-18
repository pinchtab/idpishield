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

	// ModeStrict runs the full guardrail pipeline without early-exit optimization.
	ModeStrict Mode = "strict"
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
	case "strict":
		return ModeStrict
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
	case "strict":
		return ModeStrict, nil
	default:
		return "", fmt.Errorf("invalid mode %q: expected fast, balanced, deep, or strict", s)
	}
}

// ScannerLayer identifies the pipeline layer that produced scanner output.
type ScannerLayer string

const (
	ScannerLayerHeuristics ScannerLayer = "heuristics"
	ScannerLayerCustom     ScannerLayer = "custom"
	ScannerLayerVector     ScannerLayer = "vector"
	ScannerLayerLLM        ScannerLayer = "llm"
	ScannerLayerCanary     ScannerLayer = "canary"
)

// LayerResult contains per-layer scoring details.
type LayerResult struct {
	Layer       ScannerLayer `json:"layer"`
	Score       int          `json:"score"`
	ScannersRun int          `json:"scanners_run"`
	Matched     bool         `json:"matched"`
	EarlyExit   bool         `json:"early_exit,omitempty"`
	Categories  []string     `json:"categories,omitempty"`
	Patterns    []string     `json:"patterns,omitempty"`
	Reasons     []string     `json:"reasons,omitempty"`
}

// JudgeVerdictResult contains the LLM judge's assessment.
type JudgeVerdictResult struct {
	// IsAttack is true if the LLM judged the input as an attack.
	IsAttack bool `json:"is_attack"`

	// Confidence is the LLM's confidence level.
	// Values: "high", "medium", "low"
	Confidence string `json:"confidence"`

	// Reasoning is the LLM's explanation of its verdict.
	// Only populated when JudgeConfig.IncludeReasoningInResult is true.
	Reasoning string `json:"reasoning,omitempty"`

	// Provider identifies which LLM provider was used.
	Provider string `json:"provider"`

	// Model identifies which model was used.
	Model string `json:"model"`

	// LatencyMs is how long the LLM call took in milliseconds.
	LatencyMs int64 `json:"latency_ms"`

	// ScoreAdjustment is how much the score was changed based on verdict.
	// Positive = score increased (attack confirmed).
	// Negative = score decreased (benign confirmed).
	ScoreAdjustment int `json:"score_adjustment"`
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
	IntentAgentHijacking    Intent = "agent-hijacking"
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

	// BanListMatches contains the specific ban rule matches that fired,
	// if any. Empty if no ban rules matched.
	// Example: ["substring:jailbreak", "competitor:OpenAI"]
	BanListMatches []string `json:"ban_list_matches"`

	// OverDefenseRisk is a heuristic score indicating possible
	// false-positive risk. Range 0.0 to 1.0. Higher values suggest
	// the score may be inflated by trigger words appearing in benign
	// context rather than representing a calibrated probability.
	OverDefenseRisk float64 `json:"over_defense_risk"`

	// IsOutputScan indicates this result was produced by AssessOutput.
	IsOutputScan bool `json:"is_output_scan"`

	// PIIFound indicates PII was detected in the output.
	PIIFound bool `json:"pii_found"`

	// PIITypes lists the types of PII detected (e.g. ["email", "phone"]).
	PIITypes []string `json:"pii_types"`

	// RedactedText contains the output text with PII replaced by
	// type tags (e.g. [REDACTED-EMAIL]). Empty if no PII detected.
	// Useful for safe logging and audit trails.
	RedactedText string `json:"redacted_text"`

	// RelevanceScore is the keyword overlap ratio between the LLM response
	// and original prompt. Range 0.0 to 1.0. Only populated for output scans
	// when originalPrompt was provided. -1.0 means not computed.
	RelevanceScore float64 `json:"relevance_score"`

	// CodeDetected indicates code was found in the LLM response.
	CodeDetected bool `json:"code_detected"`

	// HarmfulCodePatterns lists which harmful code patterns fired.
	HarmfulCodePatterns []string `json:"harmful_code_patterns"`

	// Intent classifies the primary attacker goal. Empty when no threat is detected.
	Intent Intent `json:"intent,omitempty"`

	// Layers contains per-layer pipeline output for audit/debug visibility.
	Layers []LayerResult `json:"layers,omitempty"`

	// JudgeVerdict contains the LLM judge's assessment, if enabled.
	// Nil when LLM judgment was not performed.
	JudgeVerdict *JudgeVerdictResult `json:"judge_verdict,omitempty"`
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
// A custom threshold (1–100) overrides the defaults when non-zero.
func ShouldBlock(score int, strict bool, customThreshold ...int) bool {
	threshold := 60
	if strict {
		threshold = 40
	}
	if len(customThreshold) > 0 && customThreshold[0] >= 1 && customThreshold[0] <= 100 {
		threshold = customThreshold[0]
	}
	return score >= threshold
}

// SafeResult returns a clean RiskResult with no threats detected.
func SafeResult() RiskResult {
	return RiskResult{
		Score:               0,
		Level:               "safe",
		Blocked:             false,
		Reason:              "No threats detected",
		Patterns:            []string{},
		Categories:          []string{},
		BanListMatches:      []string{},
		OverDefenseRisk:     0,
		IsOutputScan:        false,
		PIIFound:            false,
		PIITypes:            []string{},
		RedactedText:        "",
		RelevanceScore:      -1.0,
		CodeDetected:        false,
		HarmfulCodePatterns: []string{},
		Layers:              []LayerResult{},
		JudgeVerdict:        nil,
	}
}
