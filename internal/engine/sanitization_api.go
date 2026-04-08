package engine

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

// Redaction describes a single piece of content that was removed.
type Redaction struct {
	Type        RedactionType
	Original    string
	Replacement string
	Start       int
	End         int
}

// SanitizeConfig controls sanitization behavior.
type SanitizeConfig struct {
	RetainOriginal    bool
	RedactEmails      bool
	RedactPhones      bool
	RedactSSNs        bool
	RedactCreditCards bool
	RedactAPIKeys     bool
	RedactIPAddresses bool
	RedactURLs        bool
	CustomPatterns    []string
	ReplacementFormat string
}

func toInternalSanitizeConfig(cfg SanitizeConfig) sanitizeConfig {
	internalCfg := defaultSanitizeConfig()
	internalCfg.RetainOriginal = cfg.RetainOriginal
	internalCfg.RedactEmails = cfg.RedactEmails
	internalCfg.RedactPhones = cfg.RedactPhones
	internalCfg.RedactSSNs = cfg.RedactSSNs
	internalCfg.RedactCreditCards = cfg.RedactCreditCards
	internalCfg.RedactAPIKeys = cfg.RedactAPIKeys
	internalCfg.RedactIPAddresses = cfg.RedactIPAddresses
	internalCfg.RedactURLs = cfg.RedactURLs
	internalCfg.CustomPatterns = cfg.CustomPatterns
	internalCfg.ReplacementFormat = cfg.ReplacementFormat
	return internalCfg
}

func toOutputSanitizeConfig(cfg SanitizeConfig) sanitizeConfig {
	internalCfg := toInternalSanitizeConfig(cfg)
	internalCfg.RedactEmails = true
	internalCfg.RedactPhones = true
	internalCfg.RedactSSNs = true
	internalCfg.RedactURLs = true
	internalCfg.RequirePhoneContext = false
	internalCfg.RequireSSNContext = false
	internalCfg.EnableNamePatterns = true
	return internalCfg
}

func toPublicRedactions(internal []redaction) []Redaction {
	out := make([]Redaction, 0, len(internal))
	for _, r := range internal {
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

func (e *Engine) Sanitize(text string, cfg *SanitizeConfig) (string, []Redaction, error) {
	resolved := defaultSanitizeConfig()
	if cfg != nil {
		resolved = toInternalSanitizeConfig(*cfg)
	}
	cleaned, internalRedactions, err := sanitize(text, resolved)
	if err != nil {
		return "", nil, err
	}
	return cleaned, toPublicRedactions(internalRedactions), nil
}

func (e *Engine) SanitizeAndAssess(text string, cfg *SanitizeConfig) (string, []Redaction, RiskResult, error) {
	result := e.Assess(text, "")
	cleaned, redactions, err := e.Sanitize(text, cfg)
	if err != nil {
		return "", nil, SafeResult(), err
	}
	return cleaned, redactions, result, nil
}

func (e *Engine) SanitizeOutput(text string, cfg *SanitizeConfig) (string, []Redaction, error) {
	resolved := defaultOutputSanitizeConfig()
	if cfg != nil {
		resolved = toOutputSanitizeConfig(*cfg)
	}
	cleaned, internalRedactions, err := sanitize(text, resolved)
	if err != nil {
		return "", nil, err
	}
	return cleaned, toPublicRedactions(internalRedactions), nil
}
