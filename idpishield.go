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
	"time"

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
)

// RiskResult is the canonical return type for all idpishield analysis operations.
// Every client library and the service returns this exact structure.
type RiskResult = types.RiskResult

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

	// RedactIPAddresses removes IP addresses. Default: false
	// Disabled by default because IPs appear legitimately in many contexts.
	RedactIPAddresses bool

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
// Emails, phones, SSNs, credit cards, and API keys are redacted.
// IP addresses and URLs are not redacted by default.
func DefaultSanitizeConfig() SanitizeConfig {
	return SanitizeConfig{
		RetainOriginal:    true,
		RedactEmails:      true,
		RedactPhones:      true,
		RedactSSNs:        true,
		RedactCreditCards: true,
		RedactAPIKeys:     true,
		RedactIPAddresses: false,
		RedactURLs:        false,
		ReplacementFormat: "[REDACTED-%s]",
	}
}

// Shield is the main entry point for idpishield analysis.
// Safe for concurrent use by multiple goroutines.
type Shield struct {
	engine *engine.Engine
}

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
	resolvedCfg, err := engine.ResolveConfig(toEngineCfg(cfg))
	if err != nil {
		return nil, err
	}
	if err := engine.ValidateCustomRegex(resolvedCfg.CustomRegex); err != nil {
		return nil, err
	}

	eng := engine.New(resolvedCfg)
	return &Shield{
		engine: eng,
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

func toEngineCfg(cfg Config) engine.Config {
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
	}
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
