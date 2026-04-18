// Package idpishield provides defense against Indirect Prompt Injection (IDPI) attacks.
//
// It analyzes text content for hidden instructions that could hijack AI agent behavior
// when processing untrusted web content. The library operates in tiers:
//
//   - Tier 1 (library only): Fast local pattern matching with zero infrastructure.
//   - Tier 2 (library + service): Adds semantic analysis via the idpishield Python service.
//
// Basic usage:
//
//	client, err := idpishield.New(idpishield.Config{
//	    Mode: idpishield.ModeBalanced,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	result := client.Scan(webPageContent)
//	if result.Blocked {
//	    log.Printf("Blocked: %s (score: %d)", result.Reason, result.Score)
//	}
package idpishield

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/pinchtab/idpishield/internal/engine"
	"github.com/pinchtab/idpishield/internal/types"
)

// --- Type aliases (re-exported from internal/types) ---

// Mode configures analysis depth.
type Mode = types.Mode

const (
	// ModeFast performs pattern matching only against raw input.
	ModeFast = types.ModeFast

	// ModeBalanced applies normalization/preprocessing before pattern matching.
	ModeBalanced = types.ModeBalanced

	// ModeDeep includes balanced analysis plus optional service escalation.
	ModeDeep = types.ModeDeep

	// ModeStrict runs the full scanner pipeline without early exits.
	ModeStrict = types.ModeStrict
)

// RiskResult is the canonical return type for all idpishield analysis operations.
// Every client library and the service returns this exact structure.
type RiskResult = types.RiskResult
type JudgeVerdictResult = types.JudgeVerdictResult
type ScannerLayer = types.ScannerLayer
type LayerResult = types.LayerResult

const (
	ScannerLayerHeuristics = types.ScannerLayerHeuristics
	ScannerLayerCustom     = types.ScannerLayerCustom
	ScannerLayerVector     = types.ScannerLayerVector
	ScannerLayerLLM        = types.ScannerLayerLLM
	ScannerLayerCanary     = types.ScannerLayerCanary
)

// Scanner is the interface that custom scanners must implement.
// Implement this interface to add domain-specific detection logic.
type Scanner interface {
	// Name returns a unique scanner identifier.
	// Use lowercase hyphenated names (example: "medical-phi").
	Name() string

	// Scan evaluates context and returns detection details.
	// Implementations must be concurrency-safe and avoid panics.
	Scan(ctx ScanContext) ScanResult
}

// PriorityScanner is an optional scanner extension for execution ordering.
// Higher values run earlier within the same layer.
type PriorityScanner interface {
	Priority() int
}

// ScanContext contains all information available to a custom scanner.
type ScanContext struct {
	// Text is normalized text after decoding/normalization.
	Text string

	// RawText is the original input text before normalization.
	RawText string

	// URL is the source URL when available.
	URL string

	// Mode is the current scan mode.
	Mode Mode

	// IsOutputScan reports whether this scan runs in AssessOutput.
	IsOutputScan bool

	// CurrentScore is built-in score accumulated so far.
	CurrentScore int
}

// ScanResult is the return contract for custom scanners.
type ScanResult struct {
	// Score is this scanner's score contribution.
	// Valid range is 0..100.
	Score int

	// Category is the scanner category label.
	Category string

	// Reason is a human-readable explanation.
	Reason string

	// Matched reports whether detection fired.
	Matched bool

	// PatternID is an optional audit identifier.
	// If empty, the engine auto-generates one from Name().
	PatternID string

	// Metadata carries optional scanner-local debug data.
	Metadata map[string]string
}

// Intent classifies the attacker's primary goal.
type Intent = types.Intent

const (
	IntentNone              = types.IntentNone
	IntentInstructionBypass = types.IntentInstructionBypass
	IntentDataExfiltration  = types.IntentDataExfiltration
	IntentDataDestruction   = types.IntentDataDestruction
	IntentUnauthorizedTx    = types.IntentUnauthorizedTx
	IntentJailbreak         = types.IntentJailbreak
	IntentOutputSteering    = types.IntentOutputSteering
	IntentSystemCompromise  = types.IntentSystemCompromise
	IntentResourceExhaust   = types.IntentResourceExhaust
	IntentAgentHijacking    = types.IntentAgentHijacking
)

// --- Public types ---

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

	// BlockThreshold overrides the score at which content is blocked.
	// When zero the defaults apply: 40 in strict mode, 60 otherwise.
	// Must be in range 1–100 to take effect.
	BlockThreshold int

	// ServiceURL is the URL of the idpishield analysis service.
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

	// AllowOutputCode marks code in output as expected and reduces output
	// code scanner sensitivity to high-risk patterns only.
	AllowOutputCode bool

	// BanOutputCode flags any code present in output as suspicious.
	BanOutputCode bool

	// DebiasTriggers enables the trigger-word debias layer to reduce
	// false positives on benign content containing security-adjacent words.
	// When nil (not set), defaults to true for ModeBalanced and ModeFast,
	// and false for ModeDeep. Set explicitly to override mode defaults.
	DebiasTriggers *bool

	// BanSubstrings blocks any input containing these exact substrings.
	// Matching is case-insensitive. Set directly, via ConfigFile, or
	// via CLI env vars (IDPISHIELD_BAN_SUBSTRINGS) when using the CLI.
	// Environment variables are NOT loaded automatically by the library.
	// Example: []string{"ignore all instructions", "jailbreak"}
	BanSubstrings []string

	// BanTopics blocks inputs that appear to discuss these topics.
	// Topic matching uses whole-word case-insensitive matching.
	// Set directly, via ConfigFile, or via CLI env vars when using the CLI.
	// Environment variables are NOT loaded automatically by the library.
	// Example: []string{"cryptocurrency", "gambling", "adult content"}
	BanTopics []string

	// BanCompetitors blocks inputs mentioning these competitor names.
	// Useful for preventing prompt injection via competitor comparison attacks.
	// Matching is case-insensitive whole-word. Set directly, via ConfigFile,
	// or via CLI env vars when using the CLI.
	// Environment variables are NOT loaded automatically by the library.
	// Example: []string{"OpenAI", "Anthropic", "Google Gemini"}
	BanCompetitors []string

	// CustomRegex blocks inputs matching these user-supplied regex patterns.
	// Patterns are compiled once at shield initialization using Go's regexp
	// package, which guarantees linear-time matching and is NOT vulnerable
	// to ReDoS (catastrophic backtracking). Go's regexp uses RE2 semantics
	// which rejects patterns with backreferences and lookaheads that would
	// allow exponential matching.
	// Invalid patterns cause New() to return an error.
	// Example: []string{`\bORDER-[0-9]{6}\b`, `\bINTERNAL-[A-Z]{3}\b`}
	CustomRegex []string

	// ConfigFile is an optional path to a JSON or YAML file containing
	// ban list configuration. Fields in this file are MERGED with (not
	// replacing) any values already set directly in Config.
	// Supported formats: .json, .yaml, .yml
	// Example: "/etc/idpishield/rules.yaml"
	ConfigFile string

	// ExtraScanners are custom scanners that run after all built-in
	// input scanners during Assess/AssessContext.
	ExtraScanners []Scanner

	// ExtraOutputScanners are custom scanners that run after built-in
	// output scanners during AssessOutput.
	ExtraOutputScanners []Scanner

	// MaxCustomScannerScore limits score contribution per custom scanner.
	// Default is 50 when not set.
	MaxCustomScannerScore int

	// Judge configures the optional LLM-as-Judge layer.
	// When nil or zero value, LLM judgment is disabled.
	// The judge only runs when the heuristic score is within the
	// configured threshold range — off by default.
	Judge *JudgeConfig
}

// JudgeProvider identifies which LLM provider to use for judgment.
type JudgeProvider string

const (
	// JudgeProviderOllama uses a local Ollama instance.
	// Free, no API key required, runs offline.
	// Install: https://ollama.ai
	// Default model: llama3.2
	JudgeProviderOllama JudgeProvider = "ollama"

	// JudgeProviderOpenAI uses OpenAI's API.
	// Requires OPENAI_API_KEY environment variable or APIKey field.
	// Recommended model: gpt-4o-mini (cheap and fast)
	JudgeProviderOpenAI JudgeProvider = "openai"

	// JudgeProviderAnthropic uses Anthropic's API.
	// Requires ANTHROPIC_API_KEY environment variable or APIKey field.
	// Recommended model: claude-haiku-4-5 (cheapest Claude model)
	JudgeProviderAnthropic JudgeProvider = "anthropic"

	// JudgeProviderCustom uses a custom OpenAI-compatible API endpoint.
	// Use this for LM Studio, llama.cpp server, vLLM, etc.
	JudgeProviderCustom JudgeProvider = "custom"
)

// JudgeConfig configures the optional LLM-as-Judge layer.
type JudgeConfig struct {
	// Provider specifies which LLM provider to use.
	Provider JudgeProvider

	// Model is the model identifier to use.
	// Defaults per provider:
	//   ollama:    "llama3.2"
	//   openai:    "gpt-4o-mini"
	//   anthropic: "claude-haiku-4-5-20251001"
	//   custom:    must be set explicitly
	Model string

	// APIKey is the API key for cloud providers.
	// If empty, falls back to environment variables:
	//   openai:    OPENAI_API_KEY
	//   anthropic: ANTHROPIC_API_KEY
	// Not used for Ollama or Custom providers.
	APIKey string

	// BaseURL is the API endpoint.
	// Defaults per provider:
	//   ollama:    "http://localhost:11434"
	//   openai:    "https://api.openai.com/v1"
	//   anthropic: "https://api.anthropic.com/v1"
	//   custom:    must be set explicitly
	BaseURL string

	// ScoreThreshold is the minimum heuristic score that triggers
	// LLM judgment. Only scores >= this value get sent to the LLM.
	// Default: 25 (only uncertain/suspicious inputs get judged)
	// Set higher (e.g. 40) to only judge near-block cases.
	// Set to 0 to judge ALL inputs (expensive — not recommended).
	ScoreThreshold int

	// ScoreMaxForJudge is the maximum heuristic score that triggers
	// LLM judgment. Scores above this are already clearly attacks
	// and don't need LLM confirmation.
	// Default: 75 (clear attacks don't need second opinion)
	ScoreMaxForJudge int

	// TimeoutSeconds is the HTTP request timeout for LLM calls.
	// Default: 10 seconds.
	// Set lower for latency-sensitive applications.
	TimeoutSeconds int

	// MaxTokens limits the LLM response length.
	// Default: 150 (we only need a short verdict)
	MaxTokens int

	// SystemPrompt overrides the default judge system prompt.
	// Leave empty to use the built-in prompt.
	// The built-in prompt instructs the LLM to respond with
	// JSON containing "verdict" and "reasoning" fields.
	SystemPrompt string

	// ScoreBoostOnAttack is added to the heuristic score when
	// the LLM judges the input as an attack.
	// Default: 30
	ScoreBoostOnAttack int

	// ScorePenaltyOnBenign is subtracted from the heuristic score
	// when the LLM judges the input as benign.
	// Default: 15
	ScorePenaltyOnBenign int

	// IncludeReasoningInResult includes the LLM's reasoning text
	// in the RiskResult for debugging and audit purposes.
	// Default: true
	IncludeReasoningInResult bool
}

// applyJudgeDefaults applies provider-specific defaults and env fallbacks.
func applyJudgeDefaults(cfg *JudgeConfig) {
	if cfg == nil {
		return
	}

	if cfg.Model == "" {
		switch cfg.Provider {
		case JudgeProviderOllama:
			cfg.Model = "llama3.2"
		case JudgeProviderOpenAI:
			cfg.Model = "gpt-4o-mini"
		case JudgeProviderAnthropic:
			cfg.Model = "claude-haiku-4-5-20251001"
		}
	}

	if cfg.BaseURL == "" {
		switch cfg.Provider {
		case JudgeProviderOllama:
			cfg.BaseURL = "http://localhost:11434"
		case JudgeProviderOpenAI:
			cfg.BaseURL = "https://api.openai.com/v1"
		case JudgeProviderAnthropic:
			cfg.BaseURL = "https://api.anthropic.com/v1"
		}
	}

	if cfg.ScoreThreshold == 0 && cfg.ScoreMaxForJudge == 0 {
		cfg.ScoreThreshold = 25
		cfg.ScoreMaxForJudge = 75
	} else if cfg.ScoreMaxForJudge == 0 {
		cfg.ScoreMaxForJudge = 75
	}
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 10
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = 150
	}
	if cfg.ScoreBoostOnAttack == 0 {
		cfg.ScoreBoostOnAttack = 30
	}
	if cfg.ScorePenaltyOnBenign == 0 {
		cfg.ScorePenaltyOnBenign = 15
	}

	cfg.IncludeReasoningInResult = true

	if cfg.APIKey == "" {
		switch cfg.Provider {
		case JudgeProviderOpenAI:
			cfg.APIKey = os.Getenv("OPENAI_API_KEY")
		case JudgeProviderAnthropic:
			cfg.APIKey = os.Getenv("ANTHROPIC_API_KEY")
		}
	}
}

func isZeroJudgeConfig(cfg *JudgeConfig) bool {
	if cfg == nil {
		return true
	}

	return cfg.Provider == "" &&
		cfg.Model == "" &&
		cfg.APIKey == "" &&
		cfg.BaseURL == "" &&
		cfg.ScoreThreshold == 0 &&
		cfg.ScoreMaxForJudge == 0 &&
		cfg.TimeoutSeconds == 0 &&
		cfg.MaxTokens == 0 &&
		cfg.SystemPrompt == "" &&
		cfg.ScoreBoostOnAttack == 0 &&
		cfg.ScorePenaltyOnBenign == 0 &&
		!cfg.IncludeReasoningInResult
}

const defaultMaxCustomScannerScore = 50

var reservedScannerNames = map[string]bool{
	"secrets":                true,
	"gibberish":              true,
	"toxicity":               true,
	"emotional-manipulation": true,
	"ban-substring":          true,
	"ban-topic":              true,
	"ban-competitor":         true,
	"custom-regex":           true,
	"system-prompt-leak":     true,
	"malicious-url":          true,
	"pii-leak":               true,
	"harmful-code":           true,
	"relevance-drift":        true,
	"output-gibberish":       true,
}

// RedactionType identifies what kind of content was redacted.
type RedactionType string

const (
	RedactionTypeEmail      RedactionType = "email"
	RedactionTypePhone      RedactionType = "phone"
	RedactionTypeSSN        RedactionType = "ssn"
	RedactionTypeCreditCard RedactionType = "credit-card"
	RedactionTypeAPIKey     RedactionType = "api-key"
	RedactionTypeIPAddress  RedactionType = "ip-address"
	RedactionTypeURL        RedactionType = "url"
	RedactionTypeName       RedactionType = "name"
	RedactionTypeCustom     RedactionType = "custom"
)

// Redaction describes a single piece of content that was removed
// or replaced during sanitization.
type Redaction struct {
	// Type is the category of redacted content.
	Type RedactionType

	// Original is the original text that was replaced.
	// May be empty if RetainOriginal is false in SanitizeConfig.
	Original string

	// Replacement is the tag that replaced the original text.
	// Example: "[REDACTED-EMAIL]"
	Replacement string

	// Start is the byte offset of the original match in the input text.
	Start int

	// End is the byte offset immediately after the match.
	End int
}

// SanitizeConfig controls sanitization behavior.
type SanitizeConfig struct {
	// RetainOriginal controls whether Redaction.Original is populated.
	// Set to false in high-security environments to avoid storing
	// the sensitive value even in memory.
	// Default: true
	RetainOriginal bool

	// RedactEmails removes email addresses. Default: true
	RedactEmails bool

	// RedactPhones removes phone numbers. Default: true
	RedactPhones bool

	// RedactSSNs removes Social Security Numbers. Default: true
	RedactSSNs bool

	// RedactCreditCards removes credit card numbers. Default: true
	RedactCreditCards bool

	// RedactAPIKeys removes API keys and tokens. Default: true
	RedactAPIKeys bool

	// RedactIPAddresses removes IP addresses. Default: true
	RedactIPAddresses bool

	// RedactNames removes detected person-name pairs. Default: false.
	// Name redaction is intentionally opt-in because names are prone to
	// false positives in ordinary prose and documentation.
	RedactNames bool

	// RedactURLs removes or masks URLs. Default: false
	// Disabled by default because URLs are common in legitimate text.
	RedactURLs bool

	// CustomPatterns is a list of additional regex patterns to redact.
	// Each pattern should use one capture group when only part of the
	// match should be replaced.
	CustomPatterns []string

	// ReplacementFormat controls how redactions are formatted.
	// Default: "[REDACTED-%s]" where %s is the uppercase type name.
	ReplacementFormat string
}

// DefaultSanitizeConfig returns a SanitizeConfig with safe defaults.
// Emails, phones, SSNs, credit cards, API keys, and IP addresses are redacted.
// Name and URL redaction are not enabled by default.
func DefaultSanitizeConfig() SanitizeConfig {
	return SanitizeConfig{
		RetainOriginal:    true,
		RedactEmails:      true,
		RedactPhones:      true,
		RedactSSNs:        true,
		RedactCreditCards: true,
		RedactAPIKeys:     true,
		RedactIPAddresses: true,
		RedactNames:       false,
		RedactURLs:        false,
		ReplacementFormat: "[REDACTED-%s]",
	}
}

// Shield is the main entry point for idpishield analysis.
// Safe for concurrent use by multiple goroutines.
type Shield struct {
	mu              sync.RWMutex
	engine          *engine.Engine
	baseCfg         Config
	scannerRegistry map[string]Scanner
}

var (
	globalScannerRegistryMu sync.RWMutex
	globalScannerRegistry   = map[string]Scanner{}
)

// New creates a new Shield with the given configuration.
// Returns an error if ConfigFile is set and cannot be read or parsed,
// or if any CustomRegex pattern fails to compile.
//
// Migration note: In v0.2.0 this function began returning an error.
// For simple configurations without ConfigFile or CustomRegex,
// the error will always be nil and can be safely ignored with:
//
//	shield, _ := idpishield.New(cfg)
//
// However, checking the error is strongly recommended in production.
func New(cfg Config) (*Shield, error) {
	if err := validateScanners(cfg.ExtraScanners, "ExtraScanners"); err != nil {
		return nil, err
	}
	if err := validateScanners(cfg.ExtraOutputScanners, "ExtraOutputScanners"); err != nil {
		return nil, err
	}

	if cfg.Judge != nil {
		judgeCfg := *cfg.Judge
		cfg.Judge = &judgeCfg

		if isZeroJudgeConfig(cfg.Judge) {
			cfg.Judge = nil
		} else {
			if strings.TrimSpace(string(cfg.Judge.Provider)) == "" {
				return nil, fmt.Errorf("JudgeConfig.Provider must be set")
			}

			switch cfg.Judge.Provider {
			case JudgeProviderOllama, JudgeProviderOpenAI, JudgeProviderAnthropic, JudgeProviderCustom:
				// valid provider
			default:
				return nil, fmt.Errorf("unknown JudgeConfig.Provider %q", cfg.Judge.Provider)
			}

			applyJudgeDefaults(cfg.Judge)

			if cfg.Judge.Provider == JudgeProviderCustom && strings.TrimSpace(cfg.Judge.BaseURL) == "" {
				return nil, fmt.Errorf("JudgeConfig.BaseURL must be set for custom provider")
			}

		}
	}

	resolvedCfg, err := engine.ResolveConfig(toEngineCfg(cfg))
	if err != nil {
		return nil, err
	}
	if err := engine.ValidateCustomRegex(resolvedCfg.CustomRegex); err != nil {
		return nil, err
	}

	eng := engine.New(resolvedCfg)
	registry := snapshotGlobalScannerRegistry()
	return &Shield{
		engine:          eng,
		baseCfg:         cfg,
		scannerRegistry: registry,
	}, nil
}

// MustNew creates a new Shield and panics if initialization fails.
// Use only in tests or main() where error handling is impractical.
func MustNew(cfg Config) *Shield {
	s, err := New(cfg)
	if err != nil {
		panic("idpishield.MustNew: " + err.Error())
	}
	return s
}

// BoolPtr returns a pointer to a bool value.
// Use with Config.DebiasTriggers to explicitly set the flag.
func BoolPtr(b bool) *bool { return &b }

// Assess analyzes text for indirect prompt injection threats.
// Returns a RiskResult with score, severity level, and matched patterns.
func (s *Shield) Assess(text, url string) RiskResult {
	return s.engine.Assess(text, url)
}

// AssessContext is like Assess but accepts a context for service call cancellation.
func (s *Shield) AssessContext(ctx context.Context, text, sourceURL string) RiskResult {
	return s.engine.AssessContext(ctx, text, sourceURL)
}

// AssessOutput scans LLM response text for output-side risks including
// system prompt leakage, malicious URLs, PII exposure, harmful code,
// and response relevance drift. The originalPrompt parameter is the
// user's original input - used for relevance comparison.
// Pass an empty string for originalPrompt if not available.
//
// Output scanning uses a different scoring model than input scanning:
// it focuses on what the LLM produced, not what was injected into it.
func (s *Shield) AssessOutput(text, originalPrompt string) RiskResult {
	return s.engine.AssessOutput(text, originalPrompt)
}

// AssessPair scans both the input prompt and the LLM response,
// returning both results. This is the recommended method for
// full input->output protection in production LLM applications.
//
// Example:
//
//	inputResult, outputResult := shield.AssessPair(userInput, llmResponse)
//	if inputResult.Blocked || outputResult.Blocked {
//		// reject
//	}
func (s *Shield) AssessPair(inputText, outputText string) (inputResult RiskResult, outputResult RiskResult) {
	inputResult = s.Assess(inputText, "")
	outputResult = s.AssessOutput(outputText, inputText)
	return inputResult, outputResult
}

// Sanitize scans text for sensitive content and returns a cleaned
// version with sensitive data replaced by type tags.
// Uses DefaultSanitizeConfig if cfg is nil.
func (s *Shield) Sanitize(text string, cfg *SanitizeConfig) (cleanText string, redactions []Redaction, err error) {
	var engineCfg *engine.SanitizeConfig
	if cfg != nil {
		resolved := toEngineSanitizeConfig(*cfg)
		engineCfg = &resolved
	}

	cleanText, engineRedactions, err := s.engine.Sanitize(text, engineCfg)
	if err != nil {
		return "", nil, err
	}
	return cleanText, toPublicRedactions(engineRedactions), nil
}

// SanitizeAndAssess scans text, sanitizes it, and returns a risk assessment.
// The risk assessment runs on the original text.
func (s *Shield) SanitizeAndAssess(text string, cfg *SanitizeConfig) (cleanText string, redactions []Redaction, result RiskResult, err error) {
	var engineCfg *engine.SanitizeConfig
	if cfg != nil {
		resolved := toEngineSanitizeConfig(*cfg)
		engineCfg = &resolved
	}

	cleanText, engineRedactions, result, err := s.engine.SanitizeAndAssess(text, engineCfg)
	if err != nil {
		return "", nil, RiskResult{}, err
	}
	return cleanText, toPublicRedactions(engineRedactions), result, nil
}

// SanitizeOutput is identical to Sanitize but tuned for LLM output text.
func (s *Shield) SanitizeOutput(text string, cfg *SanitizeConfig) (cleanText string, redactions []Redaction, err error) {
	var engineCfg *engine.SanitizeConfig
	if cfg != nil {
		resolved := toEngineSanitizeConfig(*cfg)
		engineCfg = &resolved
	}

	cleanText, engineRedactions, err := s.engine.SanitizeOutput(text, engineCfg)
	if err != nil {
		return "", nil, err
	}
	return cleanText, toPublicRedactions(engineRedactions), nil
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

// InjectCanary appends a unique hidden canary token to the prompt.
// The caller must store the returned token and pass it to CheckCanary
// after receiving the LLM response.
//
// Returns the augmented prompt and the injected token.
// Returns an error only if the system's random source fails.
//
// Example usage:
//
//	augmented, token, err := shield.InjectCanary(myPrompt)
//	if err != nil { ... }
//	response := callLLM(augmented)
//	result := shield.CheckCanary(response, token)
//	if result.Found {
//		log.Println("canary detected in response: possible goal hijacking")
//	}
func (s *Shield) InjectCanary(prompt string) (injectedPrompt string, token string, err error) {
	return injectCanary(prompt)
}

// CheckCanary scans the LLM response for the canary token returned by InjectCanary.
// Returns a CanaryResult with Found=true if the token appears in the response,
// which may suggest prompt leakage (though not definitive proof).
func (s *Shield) CheckCanary(response, token string) CanaryResult {
	return checkCanary(response, token)
}

// RegisterScanner registers a scanner globally by its Name().
// Invalid scanners (nil, empty name, reserved names) are ignored.
func RegisterScanner(scanner Scanner) {
	name, ok := normalizedScannerName(scanner)
	if !ok {
		return
	}

	globalScannerRegistryMu.Lock()
	globalScannerRegistry[name] = scanner
	globalScannerRegistryMu.Unlock()
}

// RegisterScanner registers a scanner for this Shield instance by Name().
// Invalid scanners (nil, empty name, reserved names) are ignored.
func (s *Shield) RegisterScanner(scanner Scanner) {
	name, ok := normalizedScannerName(scanner)
	if !ok || s == nil {
		return
	}

	s.mu.Lock()
	if s.scannerRegistry == nil {
		s.scannerRegistry = map[string]Scanner{}
	}
	s.scannerRegistry[name] = scanner
	s.mu.Unlock()
}

// WithScanners enables registered scanners by name for this Shield instance.
// Unknown names are ignored. Built-in scanners always run.
func (s *Shield) WithScanners(names ...string) *Shield {
	if s == nil {
		return s
	}

	s.mu.RLock()
	baseCfg := s.baseCfg
	registry := cloneScannerRegistry(s.scannerRegistry)
	s.mu.RUnlock()

	selected := make([]Scanner, 0, len(names))
	for _, name := range names {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		scanner, ok := registry[key]
		if !ok || scanner == nil {
			continue
		}
		selected = append(selected, scanner)
	}

	baseExtras := append([]Scanner(nil), baseCfg.ExtraScanners...)
	cfg := baseCfg
	cfg.ExtraScanners = mergeScannersByName(baseExtras, selected)

	resolvedCfg, err := engine.ResolveConfig(toEngineCfg(cfg))
	if err != nil {
		return s
	}
	if err := engine.ValidateCustomRegex(resolvedCfg.CustomRegex); err != nil {
		return s
	}

	return &Shield{
		engine:          engine.New(resolvedCfg),
		baseCfg:         cfg,
		scannerRegistry: registry,
	}
}

// --- Functions ---

// ParseMode converts a string to a Mode value.
// Returns ModeBalanced for unrecognized values.
func ParseMode(s string) Mode {
	return types.ParseMode(s)
}

// ParseModeStrict converts a string to a Mode value and returns an error for unsupported values.
// Empty input defaults to ModeBalanced.
func ParseModeStrict(s string) (Mode, error) {
	return types.ParseModeStrict(s)
}

// ScoreToLevel maps a 0–100 score to its corresponding severity level.
func ScoreToLevel(score int) string {
	return types.ScoreToLevel(score)
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

// ScanHelpers provides utility methods for custom scanner authors.
type ScanHelpers struct{}

// Helpers returns helper methods for custom scanner implementations.
func Helpers() ScanHelpers { return ScanHelpers{} }

// ContainsAny reports whether text contains any phrase (case-insensitive).
func (h ScanHelpers) ContainsAny(text string, phrases []string) bool {
	lower := strings.ToLower(text)
	for _, phrase := range phrases {
		trimmed := strings.ToLower(strings.TrimSpace(phrase))
		if trimmed == "" {
			continue
		}
		if strings.Contains(lower, trimmed) {
			return true
		}
	}
	return false
}

// ContainsAll reports whether text contains all phrases (case-insensitive).
func (h ScanHelpers) ContainsAll(text string, phrases []string) bool {
	lower := strings.ToLower(text)
	for _, phrase := range phrases {
		trimmed := strings.ToLower(strings.TrimSpace(phrase))
		if trimmed == "" {
			continue
		}
		if !strings.Contains(lower, trimmed) {
			return false
		}
	}
	return true
}

// WordCount returns the number of words in text.
func (h ScanHelpers) WordCount(text string) int {
	return len(strings.Fields(text))
}

// ContainsWholeWord reports whether text contains word as a whole word.
func (h ScanHelpers) ContainsWholeWord(text string, word string) bool {
	needle := strings.ToLower(strings.TrimSpace(word))
	if needle == "" {
		return false
	}

	textRunes := []rune(strings.ToLower(text))
	needleRunes := []rune(needle)
	needleLen := len(needleRunes)
	if needleLen == 0 || len(textRunes) < needleLen {
		return false
	}

	for i := 0; i <= len(textRunes)-needleLen; i++ {
		if string(textRunes[i:i+needleLen]) != needle {
			continue
		}
		beforeOK := i == 0 || !isWordRune(textRunes[i-1])
		afterPos := i + needleLen
		afterOK := afterPos == len(textRunes) || !isWordRune(textRunes[afterPos])
		if beforeOK && afterOK {
			return true
		}
	}

	return false
}

// CountOccurrences counts case-insensitive phrase occurrences.
func (h ScanHelpers) CountOccurrences(text string, phrase string) int {
	needle := strings.ToLower(strings.TrimSpace(phrase))
	if needle == "" {
		return 0
	}
	return strings.Count(strings.ToLower(text), needle)
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

func validateScanners(scanners []Scanner, fieldName string) error {
	seen := make(map[string]bool, len(scanners))
	for i, s := range scanners {
		if s == nil {
			return fmt.Errorf("%s[%d] is nil", fieldName, i)
		}
		name := strings.TrimSpace(s.Name())
		if name == "" {
			return fmt.Errorf("%s[%d].Name() returned empty string", fieldName, i)
		}
		key := strings.ToLower(name)
		if seen[key] {
			return fmt.Errorf("%s[%d]: duplicate scanner name %q", fieldName, i, name)
		}
		if isReservedScannerName(name) {
			return fmt.Errorf("%s[%d]: scanner name %q is reserved", fieldName, i, name)
		}
		seen[key] = true
	}
	return nil
}

func isReservedScannerName(name string) bool {
	_, ok := reservedScannerNames[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func normalizedScannerName(scanner Scanner) (string, bool) {
	if scanner == nil {
		return "", false
	}
	name := strings.ToLower(strings.TrimSpace(scanner.Name()))
	if name == "" || isReservedScannerName(name) {
		return "", false
	}
	return name, true
}

func snapshotGlobalScannerRegistry() map[string]Scanner {
	globalScannerRegistryMu.RLock()
	defer globalScannerRegistryMu.RUnlock()

	if len(globalScannerRegistry) == 0 {
		return map[string]Scanner{}
	}
	out := make(map[string]Scanner, len(globalScannerRegistry))
	for k, v := range globalScannerRegistry {
		out[k] = v
	}
	return out
}

func cloneScannerRegistry(in map[string]Scanner) map[string]Scanner {
	if len(in) == 0 {
		return map[string]Scanner{}
	}
	out := make(map[string]Scanner, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func mergeScannersByName(base []Scanner, extras []Scanner) []Scanner {
	out := make([]Scanner, 0, len(base)+len(extras))
	seen := make(map[string]struct{}, len(base)+len(extras))

	for _, scanner := range base {
		name, ok := normalizedScannerName(scanner)
		if !ok {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, scanner)
	}

	for _, scanner := range extras {
		name, ok := normalizedScannerName(scanner)
		if !ok {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, scanner)
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

func toEngineCfg(cfg Config) engine.Config {
	maxCustomScore := cfg.MaxCustomScannerScore
	if maxCustomScore <= 0 {
		maxCustomScore = defaultMaxCustomScannerScore
	}

	return engine.Config{
		Mode:                           cfg.Mode,
		AllowedDomains:                 cfg.AllowedDomains,
		StrictMode:                     cfg.StrictMode,
		BlockThreshold:                 cfg.BlockThreshold,
		ServiceURL:                     cfg.ServiceURL,
		ServiceTimeout:                 cfg.ServiceTimeout,
		ServiceRetries:                 cfg.ServiceRetries,
		ServiceCircuitFailureThreshold: cfg.ServiceCircuitFailureThreshold,
		ServiceCircuitCooldown:         cfg.ServiceCircuitCooldown,
		MaxInputBytes:                  cfg.MaxInputBytes,
		MaxDecodeDepth:                 cfg.MaxDecodeDepth,
		MaxDecodedVariants:             cfg.MaxDecodedVariants,
		AllowOutputCode:                cfg.AllowOutputCode,
		BanOutputCode:                  cfg.BanOutputCode,
		DebiasTriggers:                 cfg.DebiasTriggers,
		BanSubstrings:                  cfg.BanSubstrings,
		BanTopics:                      cfg.BanTopics,
		BanCompetitors:                 cfg.BanCompetitors,
		CustomRegex:                    cfg.CustomRegex,
		ConfigFile:                     cfg.ConfigFile,
		ExtraScanners:                  toEngineScanners(cfg.ExtraScanners),
		ExtraOutputScanners:            toEngineScanners(cfg.ExtraOutputScanners),
		MaxCustomScannerScore:          maxCustomScore,
		Judge:                          toEngineJudgeConfig(cfg.Judge),
	}
}

func toEngineJudgeConfig(cfg *JudgeConfig) *engine.JudgeConfig {
	if cfg == nil {
		return nil
	}

	return &engine.JudgeConfig{
		Provider:                 strings.TrimSpace(string(cfg.Provider)),
		Model:                    strings.TrimSpace(cfg.Model),
		APIKey:                   strings.TrimSpace(cfg.APIKey),
		BaseURL:                  strings.TrimSpace(cfg.BaseURL),
		ScoreThreshold:           cfg.ScoreThreshold,
		ScoreMaxForJudge:         cfg.ScoreMaxForJudge,
		TimeoutSeconds:           cfg.TimeoutSeconds,
		MaxTokens:                cfg.MaxTokens,
		SystemPrompt:             cfg.SystemPrompt,
		ScoreBoostOnAttack:       cfg.ScoreBoostOnAttack,
		ScorePenaltyOnBenign:     cfg.ScorePenaltyOnBenign,
		IncludeReasoningInResult: cfg.IncludeReasoningInResult,
	}
}

type engineScannerAdapter struct {
	scanner Scanner
}

func (a *engineScannerAdapter) Name() string {
	if a == nil || a.scanner == nil {
		return ""
	}
	return a.scanner.Name()
}

func (a *engineScannerAdapter) Priority() int {
	if a == nil || a.scanner == nil {
		return 0
	}
	if p, ok := a.scanner.(PriorityScanner); ok {
		return p.Priority()
	}
	return 0
}

func (a *engineScannerAdapter) Scan(ctx engine.ExternalScanContext) engine.ExternalScanResult {
	if a == nil || a.scanner == nil {
		return engine.ExternalScanResult{}
	}

	publicCtx := ScanContext{
		Text:         ctx.Text,
		RawText:      ctx.RawText,
		URL:          ctx.URL,
		Mode:         ctx.Mode,
		IsOutputScan: ctx.IsOutputScan,
		CurrentScore: ctx.CurrentScore,
	}

	publicResult := a.scanner.Scan(publicCtx)
	var metadata map[string]string
	if len(publicResult.Metadata) > 0 {
		metadata = make(map[string]string, len(publicResult.Metadata))
		for k, v := range publicResult.Metadata {
			metadata[k] = v
		}
	}

	return engine.ExternalScanResult{
		Score:     publicResult.Score,
		Category:  publicResult.Category,
		Reason:    publicResult.Reason,
		Matched:   publicResult.Matched,
		PatternID: publicResult.PatternID,
		Metadata:  metadata,
	}
}

func toEngineScanners(scanners []Scanner) []engine.ConfigScanner {
	if len(scanners) == 0 {
		return nil
	}
	out := make([]engine.ConfigScanner, 0, len(scanners))
	for _, s := range scanners {
		if s == nil {
			continue
		}
		out = append(out, &engineScannerAdapter{scanner: s})
	}
	return out
}

func toEngineSanitizeConfig(cfg SanitizeConfig) engine.SanitizeConfig {
	return engine.SanitizeConfig{
		RetainOriginal:    cfg.RetainOriginal,
		RedactEmails:      cfg.RedactEmails,
		RedactPhones:      cfg.RedactPhones,
		RedactSSNs:        cfg.RedactSSNs,
		RedactCreditCards: cfg.RedactCreditCards,
		RedactAPIKeys:     cfg.RedactAPIKeys,
		RedactIPAddresses: cfg.RedactIPAddresses,
		RedactNames:       cfg.RedactNames,
		RedactURLs:        cfg.RedactURLs,
		CustomPatterns:    cfg.CustomPatterns,
		ReplacementFormat: cfg.ReplacementFormat,
	}
}

func toPublicRedactions(in []engine.Redaction) []Redaction {
	out := make([]Redaction, 0, len(in))
	for _, r := range in {
		out = append(out, Redaction{
			Type:        RedactionType(r.Type),
			Original:    r.Original,
			Replacement: r.Replacement,
			Start:       r.Start,
			End:         r.End,
		})
	}
	return out
}
