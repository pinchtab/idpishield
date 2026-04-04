// Debias heuristics reduce false positives from trigger-word-heavy benign text.
//
// The debias layer is applied only in trigger-dominant contexts and uses:
//  1. Payload classification (dumb-bot/spam/documentation/developer/attack)
//  2. Context scoring (0-100) from prose/documentation/developer-quality signals
//  3. Penalty scaling that never reduces strong attack payloads
//
// Real attacks are explicitly protected: attack-classified payloads and payloads
// with non-zero injection score are never reduced.
package engine

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type payloadType string

const (
	payloadTypeUnknown       payloadType = "unknown"
	payloadTypeDumbBot       payloadType = "dumb-bot"
	payloadTypeSpam          payloadType = "spam"
	payloadTypeDocumentation payloadType = "documentation"
	payloadTypeDeveloper     payloadType = "developer"
	payloadTypeAttack        payloadType = "attack"
)

const debiasWeakPenaltyMax = 15
const debiasStrongPenaltyMax = 25
const debiasDumbBotPenalty = 15
const debiasSpamPenalty = 10
const debiasDocPenalty = 10
const debiasDevPenalty = 5
const debiasPayloadPenaltyCap = 30
const debiasOverDefenseDivisor = 30.0

const contextScoreMax = 100
const contextScoreLongContentThreshold = 300
const contextScoreModerateContentThreshold = 100
const contextScoreSentenceBoundaryMin = 3
const contextScoreConnectorMin = 2
const contextScoreDeveloperKeywordMin = 2
const contextScoreAverageWordLenMin = 4.0
const contextScoreAverageWordLenMax = 8.0
const contextScoreLongTokenThreshold = 40
const contextScoreAllCapsWordMinLength = 2
const contextScoreAllCapsConsecutiveMin = 3
const contextScoreScaleFullThreshold = 60
const contextScoreScaleMediumThreshold = 30
const contextScoreScaleLowThreshold = 10
const contextScoreScaleMediumPercent = 60
const contextScoreScaleLowPercent = 30

const payloadDumbBotMaxLength = 300
const payloadDumbBotKeywordMin = 2
const payloadSpamKeywordMin = 1
const payloadDocumentationKeywordMin = 2

const contextScoreLongContentPoints = 15
const contextScoreModerateContentPoints = 10
const contextScoreSentenceBoundaryPoints = 10
const contextScoreOpenersPoints = 10
const contextScoreConnectorsPoints = 10
const contextScoreDocumentationPoints = 10
const contextScoreDeveloperPoints = 10
const contextScorePolitePoints = 5
const contextScoreEndingPunctuationPoints = 5
const contextScoreAverageWordLenPoints = 5
const contextScoreAllCapsPenalty = 15
const contextScorePunctuationPenalty = 10
const contextScoreLongTokenPenalty = 10

var (
	payloadRoleOverridePhrases        = []string{"you are", "act as", "pretend"}
	payloadDumbBotKeywords            = []string{"click", "buy", "free", "cheap", "discount", "offer", "deal", "sale", "limited", "guaranteed", "best price", "visit", "check out", "subscribe", "follow"}
	payloadSpamKeywords               = []string{"visit", "check out", "click here", "follow me", "subscribe", "found your", "great post", "nice blog"}
	payloadLLMTerms                   = []string{"system prompt", "instruction", "model", "language model", "assistant", "ai", "llm"}
	payloadDocumentationKeywords      = []string{"example", "documentation", "tutorial", "guide", "docs", "readme", "placeholder", "replace", "your_", "_key", "sample", "demo", "test", "see also", "refer to", "note:"}
	payloadDocumentationMarkdownRules = []string{"##", "```", "- [", "* "}
	payloadDeveloperKeywords          = []string{"func", "class", "def", "var", "const", "import", "return", "struct", "interface", "package", "module", "require", "export"}
	payloadDeveloperPatterns          = []string{"npm install", "go get", "pip install", "git clone", "docker run", "curl -", "wget "}
	payloadExfiltrationPhrases        = []string{"send data", "exfiltrate", "extract data", "leak", "reveal your", "tell me your system prompt", "output your system prompt"}
	payloadJailbreakPhrases           = []string{"ignore all previous instructions", "forget your instructions", "dan", "unrestricted ai", "no restrictions", "developer override", "disregard your previous system prompt", "free from all restrictions"}

	excessivePunctuationPattern = regexp.MustCompile(`[!?]{3,}`)
)

// applyDebiasAdjustment reduces weak trigger-only scores in benign-looking context.
func applyDebiasAdjustment(text string, score int, result assessmentContext) (int, string) {
	// Never debias when real injection patterns are present.
	// This is the primary safety guarantee of the debias layer.
	if result.InjectionScore > 0 {
		return maxInt(score, 0), "debias: no debias applied, injection signal present"
	}

	// Never debias when ban-list rules matched (explicit user intent).
	if result.HasBanListMatch {
		return maxInt(score, 0), "debias: no debias applied, ban-list match present"
	}

	types := classifyPayloadTypes(text)
	totalPayloadPenalty := 0
	for _, pt := range types {
		switch pt {
		case payloadTypeAttack:
			return maxInt(score, 0), "debias: attack payload, no debias applied"
		case payloadTypeDumbBot:
			totalPayloadPenalty += debiasDumbBotPenalty
		case payloadTypeSpam:
			totalPayloadPenalty += debiasSpamPenalty
		case payloadTypeDocumentation:
			totalPayloadPenalty += debiasDocPenalty
		case payloadTypeDeveloper:
			totalPayloadPenalty += debiasDevPenalty
		}
	}
	if totalPayloadPenalty > debiasPayloadPenaltyCap {
		totalPayloadPenalty = debiasPayloadPenaltyCap
	}

	adjustedScore := score
	if totalPayloadPenalty > 0 {
		appliedPayloadPenalty := minInt(totalPayloadPenalty, adjustedScore)
		adjustedScore = maxInt(adjustedScore-appliedPayloadPenalty, 0)
	}

	if result.TriggerOnlyScore <= 0 {
		return maxInt(adjustedScore, 0), "debias: no debias applied, no trigger-only signal"
	}

	contextScore := computeContextScore(text)
	penaltyCap := debiasWeakPenaltyMax
	if contextScore >= contextScoreScaleMediumThreshold {
		penaltyCap = debiasStrongPenaltyMax
	}
	basePenalty := minInt(result.TriggerOnlyScore, penaltyCap)
	scaledPenalty := scaleDebiasPenalty(basePenalty, contextScore)

	// TODO: In a future version, consider weighted combination of payload
	// types rather than additive penalties to better handle edge cases
	// where many types apply simultaneously.
	totalPenalty := scaledPenalty
	if totalPenalty <= 0 {
		return maxInt(adjustedScore, 0), "debias: no debias applied, suspicious context"
	}

	totalPenalty = minInt(totalPenalty, adjustedScore)
	finalScore := maxInt(adjustedScore-totalPenalty, 0)
	return finalScore, buildDebiasExplanation(types, totalPayloadPenalty, totalPenalty)
}

// classifyPayloadTypes categorizes payloads for debias strategy selection.
func classifyPayloadTypes(text string) []payloadType {
	lower := strings.ToLower(text)
	hasInjectionKeywords := containsInjectionLikeKeywords(lower)
	hasRoleOverride := containsAny(lower, payloadRoleOverridePhrases)

	if hasInjectionKeywords && (hasRoleOverride || containsAny(lower, payloadExfiltrationPhrases) || containsAny(lower, payloadJailbreakPhrases)) {
		return []payloadType{payloadTypeAttack}
	}
	types := make([]payloadType, 0, 4)

	if isDumbBotPayload(lower, hasInjectionKeywords, hasRoleOverride) {
		types = append(types, payloadTypeDumbBot)
	}

	if isSpamPayload(lower, hasInjectionKeywords) {
		types = append(types, payloadTypeSpam)
	}

	if isDocumentationPayload(lower) {
		types = append(types, payloadTypeDocumentation)
	}

	if isDeveloperPayload(lower) {
		types = append(types, payloadTypeDeveloper)
	}

	if len(types) == 0 {
		return []payloadType{payloadTypeUnknown}
	}

	return types
}

// isDumbBotPayload checks whether text matches dumb-bot heuristics.
func isDumbBotPayload(lower string, hasInjectionKeywords, hasRoleOverride bool) bool {
	if hasInjectionKeywords || hasRoleOverride {
		return false
	}
	if len(lower) >= payloadDumbBotMaxLength {
		return false
	}
	return countContains(lower, payloadDumbBotKeywords) >= payloadDumbBotKeywordMin
}

// isSpamPayload checks whether text matches generic spam heuristics.
func isSpamPayload(lower string, hasInjectionKeywords bool) bool {
	if hasInjectionKeywords {
		return false
	}
	if !containsURLLike(lower) {
		return false
	}
	if countContains(lower, payloadSpamKeywords) < payloadSpamKeywordMin {
		return false
	}
	if containsAny(lower, payloadLLMTerms) {
		return false
	}
	return true
}

// isDocumentationPayload detects documentation/tutorial style context.
func isDocumentationPayload(lower string) bool {
	if countContains(lower, payloadDocumentationKeywords) >= payloadDocumentationKeywordMin {
		return true
	}
	return containsAny(lower, payloadDocumentationMarkdownRules)
}

// isDeveloperPayload detects code/developer-oriented context.
func isDeveloperPayload(lower string) bool {
	if countContainsWord(lower, payloadDeveloperKeywords) >= contextScoreDeveloperKeywordMin {
		return true
	}
	return containsAny(lower, payloadDeveloperPatterns)
}

// computeContextScore returns a benign-context confidence score in range [0,100].
func computeContextScore(text string) int {
	lower := strings.ToLower(text)
	score := 0

	if len(lower) > contextScoreLongContentThreshold {
		score += contextScoreLongContentPoints
	}
	if len(lower) > contextScoreModerateContentThreshold {
		score += contextScoreModerateContentPoints
	}
	if countSentenceBoundaries(lower) >= contextScoreSentenceBoundaryMin {
		score += contextScoreSentenceBoundaryPoints
	}
	if containsAny(lower, []string{"the ", "a ", "an ", "this ", "these ", "those ", "it ", "they "}) {
		score += contextScoreOpenersPoints
	}
	if countContains(lower, []string{"please", "thank", "sorry", "however", "although", "because", "therefore", "additionally"}) >= contextScoreConnectorMin {
		score += contextScoreConnectorsPoints
	}
	if containsAny(lower, []string{"example", "note:", "tip:", "warning:", "see also", "refer to", "placeholder", "replace"}) {
		score += contextScoreDocumentationPoints
	}
	if containsAny(lower, []string{"npm", "package", "config", "settings", "environment", "variable", "flag", "option"}) {
		score += contextScoreDeveloperPoints
	}
	if containsAny(lower, []string{"kindly", "appreciate", "regards", "sincerely", "hello", "hi ", "dear "}) {
		score += contextScorePolitePoints
	}
	if hasTerminalPunctuation(lower) {
		score += contextScoreEndingPunctuationPoints
	}
	if isAverageWordLengthNatural(lower) {
		score += contextScoreAverageWordLenPoints
	}

	if hasConsecutiveAllCapsWords(text, contextScoreAllCapsConsecutiveMin) {
		score -= contextScoreAllCapsPenalty
	}
	if excessivePunctuationPattern.FindStringIndex(text) != nil {
		score -= contextScorePunctuationPenalty
	}
	if hasLongNoSpaceToken(lower, contextScoreLongTokenThreshold) {
		score -= contextScoreLongTokenPenalty
	}

	if score < 0 {
		return 0
	}
	if score > contextScoreMax {
		return contextScoreMax
	}
	return score
}

// scaleDebiasPenalty converts context score buckets into penalty strength.
func scaleDebiasPenalty(basePenalty, contextScore int) int {
	if contextScore >= contextScoreScaleFullThreshold {
		return basePenalty
	}
	if contextScore >= contextScoreScaleMediumThreshold {
		return scalePercent(basePenalty, contextScoreScaleMediumPercent)
	}
	if contextScore >= contextScoreScaleLowThreshold {
		return scalePercent(basePenalty, contextScoreScaleLowPercent)
	}
	return 0
}

// scalePercent applies integer percent scaling with rounding.
func scalePercent(value, percent int) int {
	if value <= 0 || percent <= 0 {
		return 0
	}
	return (value*percent + 50) / 100
}

// buildDebiasExplanation returns a debug-friendly explanation string.
func buildDebiasExplanation(types []payloadType, payloadPenalty, contextPenalty int) string {
	totalPenalty := payloadPenalty + contextPenalty
	if totalPenalty <= 0 {
		return "debias: no debias applied"
	}
	if hasPayloadType(types, payloadTypeDocumentation) {
		return "debias: documentation context, trigger-only signals (-" + intToString(totalPenalty) + ")"
	}
	if hasPayloadType(types, payloadTypeDeveloper) {
		return "debias: developer context, trigger-only signals (-" + intToString(totalPenalty) + ")"
	}
	if hasPayloadType(types, payloadTypeDumbBot) {
		return "debias: dumb-bot payload detected (-" + intToString(totalPenalty) + ")"
	}
	if hasPayloadType(types, payloadTypeSpam) {
		return "debias: spam payload detected (-" + intToString(totalPenalty) + ")"
	}
	return "debias: trigger-only signals reduced (-" + intToString(totalPenalty) + ")"
}

func hasPayloadType(types []payloadType, want payloadType) bool {
	for _, pt := range types {
		if pt == want {
			return true
		}
	}
	return false
}

// containsURLLike reports whether text includes a simple URL/domain indicator.
func containsURLLike(lower string) bool {
	return strings.Contains(lower, "http://") || strings.Contains(lower, "https://") || strings.Contains(lower, ".com") || strings.Contains(lower, ".net") || strings.Contains(lower, ".org")
}

// countContainsWord counts word-like tokens with basic boundary checks.
func countContainsWord(text string, words []string) int {
	count := 0
	for _, word := range words {
		if strings.Contains(text, " "+word+" ") || strings.HasPrefix(text, word+" ") || strings.HasSuffix(text, " "+word) {
			count++
		}
	}
	return count
}

// countSentenceBoundaries approximates sentence boundaries in text.
func countSentenceBoundaries(lower string) int {
	return strings.Count(lower, ". ") + strings.Count(lower, ".\n") + strings.Count(lower, "! ") + strings.Count(lower, "? ")
}

// hasTerminalPunctuation reports whether text ends with sentence punctuation.
func hasTerminalPunctuation(lower string) bool {
	trimmed := strings.TrimSpace(lower)
	if trimmed == "" {
		return false
	}
	last := trimmed[len(trimmed)-1]
	return last == '.' || last == '!' || last == '?'
}

// isAverageWordLengthNatural reports whether average token length resembles prose.
func isAverageWordLengthNatural(lower string) bool {
	words := tokenizeAlphaNumericWords(lower)
	if len(words) == 0 {
		return false
	}
	total := 0
	for _, w := range words {
		total += len(w)
	}
	avg := float64(total) / float64(len(words))
	return avg >= contextScoreAverageWordLenMin && avg <= contextScoreAverageWordLenMax
}

// tokenizeAlphaNumericWords extracts lowercase alphanumeric tokens from text.
func tokenizeAlphaNumericWords(text string) []string {
	fields := strings.Fields(text)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		clean := strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				return unicode.ToLower(r)
			}
			return -1
		}, f)
		if clean != "" {
			out = append(out, clean)
		}
	}
	return out
}

// hasConsecutiveAllCapsWords reports aggressive all-caps word runs.
func hasConsecutiveAllCapsWords(text string, minConsecutive int) bool {
	words := strings.Fields(text)
	consecutive := 0
	for _, w := range words {
		if isAllCapsWord(w) {
			consecutive++
			if consecutive >= minConsecutive {
				return true
			}
			continue
		}
		consecutive = 0
	}
	return false
}

// isAllCapsWord reports whether a token consists of uppercase letters.
func isAllCapsWord(word string) bool {
	letters := 0
	for _, r := range word {
		if !unicode.IsLetter(r) {
			continue
		}
		letters++
		if !unicode.IsUpper(r) {
			return false
		}
	}
	return letters >= contextScoreAllCapsWordMinLength
}

// hasLongNoSpaceToken reports potentially obfuscated long tokens.
func hasLongNoSpaceToken(lower string, threshold int) bool {
	for _, token := range strings.Fields(lower) {
		if len(token) > threshold {
			return true
		}
	}
	return false
}

// intToString converts an integer to its decimal string representation.
func intToString(v int) string {
	return strconv.Itoa(v)
}

// minInt returns the smaller of two integers.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// maxInt returns the larger of two integers.
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
