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
	RedactNames       bool
	RedactURLs        bool
	CustomPatterns    []string
	ReplacementFormat string

	RequirePhoneContext bool
	RequireSSNContext   bool
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
		RedactIPAddresses:   true,
		RedactNames:         false,
		RedactURLs:          false,
		ReplacementFormat:   defaultReplacementFormat,
		RequirePhoneContext: true,
		RequireSSNContext:   true,
	}
}

func defaultOutputSanitizeConfig() sanitizeConfig {
	cfg := defaultSanitizeConfig()
	cfg.RedactURLs = true
	cfg.RequirePhoneContext = false
	cfg.RequireSSNContext = false
	return cfg
}

func sanitize(text string, cfg sanitizeConfig) (string, []redaction, error) {
	tracked := preprocessUnicodeForSanitizeTracked(text)
	tracked = preprocessObfuscationForSanitizeTracked(tracked)
	if tracked.Value == "" {
		return "", []redaction{}, nil
	}
	if len(tracked.Value) > sanitizeMaxInputBytes {
		tracked.Value = tracked.Value[:sanitizeMaxInputBytes]
		tracked.Origins = tracked.Origins[:sanitizeMaxInputBytes]
	}

	format := strings.TrimSpace(cfg.ReplacementFormat)
	if format == "" {
		format = defaultReplacementFormat
	}

	patterns := compileCustomPatterns(cfg.CustomPatterns)
	matches := findDecodedMatches(tracked.Value, cfg)
	matches = append(matches, collectEnabledMatches(tracked.Value, cfg, patterns)...)
	resolved := resolveOverlaps(matches)

	if cfg.RedactNames {
		resolved = addNameMatchesWhenPIIPresent(tracked.Value, resolved)
		resolved = resolveOverlaps(resolved)
	}

	resolved = capMatches(resolved, sanitizeMaxMatches)
	tracked, redactions := applyReplacements(tracked, resolved, format, cfg.RetainOriginal)

	// Run one additional pass on cleaned text to catch patterns revealed after decoding.
	secondMatches := findDecodedMatches(tracked.Value, cfg)
	secondMatches = append(secondMatches, collectEnabledMatches(tracked.Value, cfg, patterns)...)
	secondResolved := capMatches(resolveOverlaps(secondMatches), sanitizeMaxMatches)
	if len(secondResolved) > 0 {
		var redactions2 []redaction
		tracked, redactions2 = applyReplacements(tracked, secondResolved, format, cfg.RetainOriginal)
		redactions = append(redactions, redactions2...)
		sort.Slice(redactions, func(i, j int) bool {
			return redactions[i].Start < redactions[j].Start
		})
	}

	return tracked.Value, redactions, nil
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
	for _, loc := range reNamePair.FindAllStringIndex(text, -1) {
		candidate := text[loc[0]:loc[1]]
		if isPlaceholderName(candidate) {
			continue
		}
		if !shouldRedactName(text, loc[0], loc[1], matches) {
			continue
		}
		matches = append(matches, redactionMatch{
			Start:    loc[0],
			End:      loc[1],
			Type:     redactionTypeName,
			Original: candidate,
			Priority: sanitizePriorityName,
		})
	}

	return matches
}

func shouldRedactName(text string, start, end int, matches []redactionMatch) bool {
	if hasNameLabelPrefix(text, start) {
		return true
	}

	strongPIICount := countStrongPIINearName(text, start, end, matches)
	return strongPIICount >= sanitizeNameMinOtherTypes
}

func isPlaceholderName(name string) bool {
	_, ok := sanitizeNamePlaceholderAllowlist[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func hasNameLabelPrefix(text string, start int) bool {
	lineStart := strings.LastIndex(text[:start], "\n") + 1
	prefix := strings.TrimSpace(strings.ToLower(text[lineStart:start]))
	return sanitizeNameLabelPattern.MatchString(prefix)
}

func countStrongPIINearName(text string, start, end int, matches []redactionMatch) int {
	count := 0
	lineStart, lineEnd := surroundingLineBounds(text, start, end)
	sentenceStart, sentenceEnd := surroundingSentenceBounds(text, start, end)

	for _, m := range matches {
		if !isStrongNameContextType(m.Type) {
			continue
		}
		if rangesOverlap(m.Start, m.End, start, end) {
			continue
		}
		if rangesOverlap(m.Start, m.End, lineStart, lineEnd) || rangesOverlap(m.Start, m.End, sentenceStart, sentenceEnd) {
			count++
		}
	}

	return count
}

func isStrongNameContextType(t redactionType) bool {
	switch t {
	case redactionTypeEmail, redactionTypePhone, redactionTypeSSN, redactionTypeCreditCard, redactionTypeAPIKey, redactionTypeIPAddress:
		return true
	default:
		return false
	}
}

func surroundingLineBounds(text string, start, end int) (int, int) {
	lineStart := strings.LastIndex(text[:start], "\n") + 1
	lineEndOffset := strings.Index(text[end:], "\n")
	if lineEndOffset < 0 {
		return lineStart, len(text)
	}
	return lineStart, end + lineEndOffset
}

func surroundingSentenceBounds(text string, start, end int) (int, int) {
	sentenceStart := strings.LastIndexAny(text[:start], ".!?\n")
	if sentenceStart < 0 {
		sentenceStart = 0
	} else {
		sentenceStart++
	}
	sentenceEndOffset := strings.IndexAny(text[end:], ".!?\n")
	if sentenceEndOffset < 0 {
		return sentenceStart, len(text)
	}
	return sentenceStart, end + sentenceEndOffset
}

func rangesOverlap(leftStart, leftEnd, rightStart, rightEnd int) bool {
	return leftStart < rightEnd && rightStart < leftEnd
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

func applyReplacements(text trackedText, matches []redactionMatch, format string, retain bool) (trackedText, []redaction) {
	if len(matches) == 0 {
		return text, []redaction{}
	}

	ordered := make([]redactionMatch, len(matches))
	copy(ordered, matches)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Start != ordered[j].Start {
			return ordered[i].Start < ordered[j].Start
		}
		return ordered[i].End < ordered[j].End
	})

	var b strings.Builder
	b.Grow(len(text.Value))
	origins := make([]originSpan, 0, len(text.Origins))
	redactions := make([]redaction, 0, len(ordered))
	cursor := 0

	for _, m := range ordered {
		if m.Start < 0 || m.End > len(text.Value) || m.Start >= m.End {
			continue
		}
		appendTrackedSlice(&b, &origins, text, cursor, m.Start)

		replacement := replacementForType(format, m.Type, m.Subtype)
		matchSpan := collapseOriginRange(text.Origins, m.Start, m.End)
		appendOriginLiteral(&b, &origins, replacement, matchSpan)

		original := originalSegment(text.Raw, matchSpan)
		if !retain {
			original = ""
		}
		redactions = append(redactions, redaction{
			Type:        m.Type,
			Original:    original,
			Replacement: replacement,
			Start:       matchSpan.Start,
			End:         matchSpan.End,
		})
		cursor = m.End
	}
	appendTrackedSlice(&b, &origins, text, cursor, len(text.Value))

	return trackedText{
		Value:   b.String(),
		Origins: origins,
		Raw:     text.Raw,
	}, redactions
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
