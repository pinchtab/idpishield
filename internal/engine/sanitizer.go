package engine

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	sanitizeMaxInputBytes = 1 << 20
	sanitizeMaxMatches    = 2048

	sanitizePriorityAPIKey = 1
	sanitizePrioritySSN    = 2
	sanitizePriorityCard   = 3
	sanitizePriorityEmail  = 4
	sanitizePriorityPhone  = 5
	sanitizePriorityIP     = 6
	sanitizePriorityURL    = 7
	sanitizePriorityDecode = 8
	sanitizePriorityCustom = 8
	sanitizePriorityName   = 9

	sanitizeNameMinOtherTypes = 1

	defaultReplacementFormat = "[REDACTED-%s]"
)

type redactionType string

const (
	redactionTypeEmail      redactionType = "email"
	redactionTypePhone      redactionType = "phone"
	redactionTypeSSN        redactionType = "ssn"
	redactionTypeCreditCard redactionType = "credit-card"
	redactionTypeAPIKey     redactionType = "api-key"
	redactionTypeIPAddress  redactionType = "ip-address"
	redactionTypeURL        redactionType = "url"
	redactionTypeName       redactionType = "name"
	redactionTypeCustom     redactionType = "custom"
)

type redaction struct {
	Type        redactionType
	Original    string
	Replacement string
	Start       int
	End         int
}

type sanitizeConfig struct {
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

	RequirePhoneContext bool
	RequireSSNContext   bool
	EnableNamePatterns  bool
}

type redactionMatch struct {
	Start    int
	End      int
	Type     redactionType
	Subtype  string
	Original string
	Priority int
}

func defaultSanitizeConfig() sanitizeConfig {
	return sanitizeConfig{
		RetainOriginal:      true,
		RedactEmails:        true,
		RedactPhones:        true,
		RedactSSNs:          true,
		RedactCreditCards:   true,
		RedactAPIKeys:       true,
		RedactIPAddresses:   false,
		RedactURLs:          false,
		ReplacementFormat:   defaultReplacementFormat,
		RequirePhoneContext: true,
		RequireSSNContext:   true,
		EnableNamePatterns:  false,
	}
}

func defaultOutputSanitizeConfig() sanitizeConfig {
	cfg := defaultSanitizeConfig()
	cfg.RedactURLs = true
	cfg.RequirePhoneContext = false
	cfg.RequireSSNContext = false
	cfg.EnableNamePatterns = true
	return cfg
}

func sanitize(text string, cfg sanitizeConfig) (string, []redaction, error) {
	preprocessed := preprocessUnicodeForSanitize(text)
	preprocessed = preprocessObfuscationForSanitize(preprocessed)
	if preprocessed == "" {
		return "", []redaction{}, nil
	}
	if len(preprocessed) > sanitizeMaxInputBytes {
		preprocessed = preprocessed[:sanitizeMaxInputBytes]
	}

	format := strings.TrimSpace(cfg.ReplacementFormat)
	if format == "" {
		format = defaultReplacementFormat
	}

	patterns := compileCustomPatterns(cfg.CustomPatterns)
	matches := findDecodedMatches(preprocessed, cfg)
	matches = append(matches, collectEnabledMatches(preprocessed, cfg, patterns)...)
	resolved := resolveOverlaps(matches)

	if cfg.EnableNamePatterns {
		resolved = addNameMatchesWhenPIIPresent(preprocessed, resolved)
		resolved = resolveOverlaps(resolved)
	}

	resolved = capMatches(resolved, sanitizeMaxMatches)
	cleaned, redactions := applyReplacements(preprocessed, resolved, format, cfg.RetainOriginal)

	// Run one additional pass on cleaned text to catch patterns revealed after decoding.
	secondMatches := findDecodedMatches(cleaned, cfg)
	secondMatches = append(secondMatches, collectEnabledMatches(cleaned, cfg, patterns)...)
	secondResolved := capMatches(resolveOverlaps(secondMatches), sanitizeMaxMatches)
	if len(secondResolved) > 0 {
		cleaned2, redactions2 := applyReplacements(cleaned, secondResolved, format, cfg.RetainOriginal)
		cleaned = cleaned2
		redactions = append(redactions, redactions2...)
		sort.Slice(redactions, func(i, j int) bool {
			return redactions[i].Start < redactions[j].Start
		})
	}

	return cleaned, redactions, nil
}

func collectEnabledMatches(text string, cfg sanitizeConfig, patterns []*regexp.Regexp) []redactionMatch {
	matches := make([]redactionMatch, 0)

	if cfg.RedactAPIKeys {
		matches = append(matches, findAPIKeyMatches(text)...)
	}
	if cfg.RedactSSNs {
		if cfg.RequireSSNContext {
			matches = append(matches, findSSNMatches(text)...)
		} else {
			matches = append(matches, findSSNMatchesWithContext(text, false)...)
		}
	}
	if cfg.RedactCreditCards {
		matches = append(matches, findCreditCardMatches(text)...)
	}
	if cfg.RedactEmails {
		matches = append(matches, findEmailMatches(text)...)
	}
	if cfg.RedactPhones {
		if cfg.RequirePhoneContext {
			matches = append(matches, findPhoneMatches(text)...)
		} else {
			matches = append(matches, findPhoneMatchesWithContext(text, false)...)
		}
	}
	if cfg.RedactIPAddresses {
		matches = append(matches, findIPMatches(text)...)
	}
	if cfg.RedactURLs {
		matches = append(matches, findURLMatches(text)...)
	}
	if len(patterns) > 0 {
		matches = append(matches, findCustomMatches(text, patterns)...)
	}

	return matches
}

func addNameMatchesWhenPIIPresent(text string, matches []redactionMatch) []redactionMatch {
	types := make(map[redactionType]struct{}, len(matches))
	for _, m := range matches {
		types[m.Type] = struct{}{}
	}
	if len(types) < sanitizeNameMinOtherTypes {
		return matches
	}

	for _, loc := range reNamePair.FindAllStringIndex(text, -1) {
		matches = append(matches, redactionMatch{
			Start:    loc[0],
			End:      loc[1],
			Type:     redactionTypeName,
			Original: text[loc[0]:loc[1]],
			Priority: sanitizePriorityName,
		})
	}

	return matches
}

func findEmailMatches(text string) []redactionMatch {
	matches := make([]redactionMatch, 0)
	for _, loc := range reEmail.FindAllStringIndex(text, -1) {
		candidate := text[loc[0]:loc[1]]
		if _, skip := sanitizeDocEmailAllowlist[strings.ToLower(candidate)]; skip {
			continue
		}
		matches = append(matches, redactionMatch{
			Start:    loc[0],
			End:      loc[1],
			Type:     redactionTypeEmail,
			Original: candidate,
			Priority: sanitizePriorityEmail,
		})
	}
	return matches
}

func findPhoneMatches(text string) []redactionMatch {
	return findPhoneMatchesWithContext(text, true)
}

func findPhoneMatchesWithContext(text string, requireContext bool) []redactionMatch {
	matches := make([]redactionMatch, 0)
	lower := strings.ToLower(text)
	for _, loc := range rePhoneUS.FindAllStringIndex(text, -1) {
		if requireContext {
			if !hasNearbyContext(lower, loc[0], loc[1], sanitizePhoneContextWords) && !hasPhonePrefix(text, loc[0]) {
				continue
			}
		}
		matches = append(matches, redactionMatch{
			Start:    loc[0],
			End:      loc[1],
			Type:     redactionTypePhone,
			Original: text[loc[0]:loc[1]],
			Priority: sanitizePriorityPhone,
		})
	}
	return matches
}

func findSSNMatches(text string) []redactionMatch {
	return findSSNMatchesWithContext(text, true)
}

func findSSNMatchesWithContext(text string, requireContext bool) []redactionMatch {
	matches := make([]redactionMatch, 0)
	lower := strings.ToLower(text)
	for _, loc := range reSSN.FindAllStringIndex(text, -1) {
		if looksLikeDate(text, loc[0], loc[1]) {
			continue
		}
		if requireContext && !hasNearbyContext(lower, loc[0], loc[1], sanitizeSSNContextWords) {
			continue
		}
		matches = append(matches, redactionMatch{
			Start:    loc[0],
			End:      loc[1],
			Type:     redactionTypeSSN,
			Original: text[loc[0]:loc[1]],
			Priority: sanitizePrioritySSN,
		})
	}
	return matches
}

func findCreditCardMatches(text string) []redactionMatch {
	matches := make([]redactionMatch, 0)
	for _, loc := range reCreditCard.FindAllStringIndex(text, -1) {
		candidate := text[loc[0]:loc[1]]
		if !luhnCheck(candidate) {
			continue
		}
		matches = append(matches, redactionMatch{
			Start:    loc[0],
			End:      loc[1],
			Type:     redactionTypeCreditCard,
			Original: candidate,
			Priority: sanitizePriorityCard,
		})
	}
	return matches
}

func findAPIKeyMatches(text string) []redactionMatch {
	result := scanSecrets(text)
	if !result.HasSecrets || result.Confidence != outputPIIConfidenceHigh {
		return []redactionMatch{}
	}

	matches := make([]redactionMatch, 0)
	for _, p := range secretsHighPatterns {
		for _, loc := range p.rx.FindAllStringIndex(text, -1) {
			matches = append(matches, redactionMatch{
				Start:    loc[0],
				End:      loc[1],
				Type:     redactionTypeAPIKey,
				Original: text[loc[0]:loc[1]],
				Priority: sanitizePriorityAPIKey,
			})
		}
	}

	for _, loc := range awsSecretKeyPattern.FindAllStringIndex(text, -1) {
		start := loc[0] - secretsAWSContextWindowBytes
		if start < 0 {
			start = 0
		}
		end := loc[1] + secretsAWSContextWindowBytes
		if end > len(text) {
			end = len(text)
		}
		if awsSecretContextPattern.FindStringIndex(text[start:end]) == nil {
			continue
		}
		matches = append(matches, redactionMatch{
			Start:    loc[0],
			End:      loc[1],
			Type:     redactionTypeAPIKey,
			Original: text[loc[0]:loc[1]],
			Priority: sanitizePriorityAPIKey,
		})
	}

	return matches
}

func findIPMatches(text string) []redactionMatch {
	matches := make([]redactionMatch, 0)
	seen := make(map[string]struct{})

	for _, loc := range rePrivateIP.FindAllStringIndex(text, -1) {
		key := fmt.Sprintf("%d:%d", loc[0], loc[1])
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		matches = append(matches, redactionMatch{
			Start:    loc[0],
			End:      loc[1],
			Type:     redactionTypeIPAddress,
			Original: text[loc[0]:loc[1]],
			Priority: sanitizePriorityIP,
		})
	}

	for _, loc := range rePublicIP.FindAllStringIndex(text, -1) {
		candidate := text[loc[0]:loc[1]]
		if !isValidIPv4(candidate) {
			continue
		}
		key := fmt.Sprintf("%d:%d", loc[0], loc[1])
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		matches = append(matches, redactionMatch{
			Start:    loc[0],
			End:      loc[1],
			Type:     redactionTypeIPAddress,
			Original: candidate,
			Priority: sanitizePriorityIP,
		})
	}

	return matches
}

func findURLMatches(text string) []redactionMatch {
	locs := reURL.FindAllStringIndex(text, -1)
	matches := make([]redactionMatch, 0, len(locs))
	for _, loc := range locs {
		matches = append(matches, redactionMatch{
			Start:    loc[0],
			End:      loc[1],
			Type:     redactionTypeURL,
			Original: text[loc[0]:loc[1]],
			Priority: sanitizePriorityURL,
		})
	}
	return matches
}

func findCustomMatches(text string, patterns []*regexp.Regexp) []redactionMatch {
	matches := make([]redactionMatch, 0, len(patterns))
	for _, re := range patterns {
		if re == nil {
			continue
		}

		if re.NumSubexp() == 1 {
			for _, loc := range re.FindAllStringSubmatchIndex(text, -1) {
				if len(loc) < 4 || loc[2] < 0 || loc[3] <= loc[2] {
					continue
				}
				matches = append(matches, redactionMatch{
					Start:    loc[2],
					End:      loc[3],
					Type:     redactionTypeCustom,
					Original: text[loc[2]:loc[3]],
					Priority: sanitizePriorityCustom,
				})
			}
			continue
		}

		for _, loc := range re.FindAllStringIndex(text, -1) {
			matches = append(matches, redactionMatch{
				Start:    loc[0],
				End:      loc[1],
				Type:     redactionTypeCustom,
				Original: text[loc[0]:loc[1]],
				Priority: sanitizePriorityCustom,
			})
		}
	}
	return matches
}

func resolveOverlaps(matches []redactionMatch) []redactionMatch {
	if len(matches) <= 1 {
		return matches
	}

	sorted := make([]redactionMatch, len(matches))
	copy(sorted, matches)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		if sorted[i].End != sorted[j].End {
			return sorted[i].End > sorted[j].End
		}
		return sorted[i].Priority < sorted[j].Priority
	})

	resolved := make([]redactionMatch, 0, len(sorted))
	for _, candidate := range sorted {
		if len(resolved) == 0 {
			resolved = append(resolved, candidate)
			continue
		}
		last := resolved[len(resolved)-1]
		if candidate.Start >= last.End {
			resolved = append(resolved, candidate)
			continue
		}
		if betterMatch(candidate, last) {
			resolved[len(resolved)-1] = candidate
		}
	}

	return resolved
}

func betterMatch(left, right redactionMatch) bool {
	if left.Priority != right.Priority {
		return left.Priority < right.Priority
	}
	leftLen := left.End - left.Start
	rightLen := right.End - right.Start
	if leftLen != rightLen {
		return leftLen > rightLen
	}
	return left.Start < right.Start
}

func applyReplacements(text string, matches []redactionMatch, format string, retain bool) (string, []redaction) {
	if len(matches) == 0 {
		return text, []redaction{}
	}

	out := text
	desc := make([]redactionMatch, len(matches))
	copy(desc, matches)
	sort.Slice(desc, func(i, j int) bool {
		return desc[i].Start > desc[j].Start
	})

	redactions := make([]redaction, 0, len(desc))
	for _, m := range desc {
		if m.Start < 0 || m.End > len(out) || m.Start >= m.End {
			continue
		}
		replacement := replacementForType(format, m.Type, m.Subtype)
		out = out[:m.Start] + replacement + out[m.End:]
		original := m.Original
		if !retain {
			original = ""
		}
		redactions = append(redactions, redaction{
			Type:        m.Type,
			Original:    original,
			Replacement: replacement,
			Start:       m.Start,
			End:         m.End,
		})
	}

	sort.Slice(redactions, func(i, j int) bool {
		return redactions[i].Start < redactions[j].Start
	})

	return out, redactions
}

func replacementForType(format string, t redactionType, subtype string) string {
	token := strings.ToUpper(string(t))
	if t == redactionTypeCustom && subtype != "" {
		token = token + "-" + strings.ToUpper(subtype)
	}
	return fmt.Sprintf(format, token)
}

func capMatches(matches []redactionMatch, max int) []redactionMatch {
	if max <= 0 || len(matches) <= max {
		return matches
	}
	return matches[:max]
}

func compileCustomPatterns(raw []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(raw))
	for _, pattern := range raw {
		trimmed := strings.TrimSpace(pattern)
		if trimmed == "" {
			continue
		}
		re, err := regexp.Compile(trimmed)
		if err != nil {
			continue
		}
		if re.NumSubexp() > 1 {
			continue
		}
		compiled = append(compiled, re)
	}
	return compiled
}
