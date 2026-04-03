package engine

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

type secretsResult struct {
	HasSecrets   bool
	MatchedTypes []string
	Confidence   string
}

const (
	secretsAWSContextWindowBytes = 50
	secretsEntropyThreshold      = 4.5
)

var secretsHighPatterns = []struct {
	name string
	rx   *regexp.Regexp
}{
	{name: "aws-access-key", rx: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{name: "anthropic-key", rx: regexp.MustCompile(`\bsk-ant-[a-zA-Z0-9\-_]{90,}\b`)},
	{name: "openai-key", rx: regexp.MustCompile(`\bsk-[a-zA-Z0-9]{48}\b`)},
	{name: "huggingface-token", rx: regexp.MustCompile(`\bhf_[a-zA-Z0-9]{37}\b`)},
	{name: "azure-sas-token", rx: regexp.MustCompile(`(?i)\bsig=[a-zA-Z0-9%]{40,}\b`)},
	{name: "github-pat-new", rx: regexp.MustCompile(`\bghp_[a-zA-Z0-9]{36}\b`)},
	{name: "github-oauth", rx: regexp.MustCompile(`\bgho_[a-zA-Z0-9]{36}\b`)},
	{name: "github-pat-classic", rx: regexp.MustCompile(`\bgithub_pat_[a-zA-Z0-9_]{59}\b`)},
	{name: "stripe-live-secret", rx: regexp.MustCompile(`\bsk_live_[a-zA-Z0-9]{24,}\b`)},
	{name: "stripe-live-pub", rx: regexp.MustCompile(`\bpk_live_[a-zA-Z0-9]{24,}\b`)},
	{name: "google-api-key", rx: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{name: "slack-token", rx: regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z\-]{10,48}\b`)},
	{name: "npm-token", rx: regexp.MustCompile(`\bnpm_[a-zA-Z0-9]{36}\b`)},
}

var secretsMediumPatterns = []struct {
	name string
	rx   *regexp.Regexp
}{
	{name: "generic-bearer", rx: regexp.MustCompile(`(?i)Bearer\s+[a-zA-Z0-9\-._~+/]{20,}`)},
	{name: "generic-api-key", rx: regexp.MustCompile(`(?i)\bapi[_\-]?key\b\s*[:=]\s*[a-zA-Z0-9\-._]{16,}`)},
	{name: "generic-password", rx: regexp.MustCompile(`(?i)\bpassword\b\s*[:=]\s*\S{8,}`)},
}

var awsSecretKeyPattern = regexp.MustCompile(`\b[0-9a-zA-Z/+]{40}\b`)
var awsSecretContextPattern = regexp.MustCompile(`(?i)\b(?:aws|secret)\b`)
var highEntropyTokenPattern = regexp.MustCompile(`\b[0-9A-Za-z]{20,}\b`)
var secretsKeywordPattern = regexp.MustCompile(`(?i)\b(?:api|key|token|secret|password|bearer|auth|credential)s?\b`)

const secretsEntropyKeywordContextType = "__entropy-keyword-context"

// scanSecrets detects credential-like patterns and entropy-based secret candidates.
func scanSecrets(text string) secretsResult {
	if strings.TrimSpace(text) == "" {
		return secretsResult{Confidence: "low"}
	}

	lowered := strings.ToLower(text)
	hasKeyword := hasSecretPrefilterKeyword(lowered)
	runFullScan := hasKeyword || len(text) >= 500

	var highTypes []string
	var mediumTypes []string

	if runFullScan {
		_, highTypes = matchHighConfidencePatterns(text)
		_, mediumTypes = matchMediumConfidencePatterns(text)
	}

	hasEntropy := matchEntropyTokens(text)
	entropyKeywordContext := hasEntropy && secretsKeywordPattern.FindStringIndex(text) != nil
	if entropyKeywordContext {
		mediumTypes = append(mediumTypes, secretsEntropyKeywordContextType)
	}
	return buildSecretsResult(highTypes, mediumTypes, hasEntropy)
}

// hasSecretPrefilterKeyword reports whether lowered text has cheap secret-like keywords.
func hasSecretPrefilterKeyword(lowered string) bool {
	return strings.Contains(lowered, "akia") ||
		strings.Contains(lowered, "ghp_") ||
		strings.Contains(lowered, "gho_") ||
		strings.Contains(lowered, "github_pat_") ||
		strings.Contains(lowered, "aiza") ||
		strings.Contains(lowered, "sk_live_") ||
		strings.Contains(lowered, "pk_live_") ||
		strings.Contains(lowered, "xox") ||
		strings.Contains(lowered, "npm_") ||
		strings.Contains(lowered, "sk-ant-") ||
		strings.Contains(lowered, "sk-") ||
		strings.Contains(lowered, "hf_") ||
		strings.Contains(lowered, "sig=") ||
		strings.Contains(lowered, "bearer") ||
		strings.Contains(lowered, "api_key") ||
		strings.Contains(lowered, "api-key") ||
		strings.Contains(lowered, "apikey") ||
		strings.Contains(lowered, "password") ||
		strings.Contains(lowered, "secret")
}

// matchHighConfidencePatterns checks all high-confidence secret patterns.
func matchHighConfidencePatterns(text string) (matched bool, types []string) {
	types = make([]string, 0, len(secretsHighPatterns)+1)
	for _, p := range secretsHighPatterns {
		if p.rx.FindStringIndex(text) != nil {
			types = append(types, p.name)
			matched = true
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
		if awsSecretContextPattern.FindStringIndex(text[start:end]) != nil {
			types = append(types, "aws-secret-key")
			matched = true
			break
		}
	}

	return matched, types
}

// matchMediumConfidencePatterns checks all medium-confidence secret patterns.
func matchMediumConfidencePatterns(text string) (matched bool, types []string) {
	types = make([]string, 0, len(secretsMediumPatterns))
	for _, p := range secretsMediumPatterns {
		if p.rx.FindStringIndex(text) != nil {
			types = append(types, p.name)
			matched = true
		}
	}
	return matched, types
}

// matchEntropyTokens checks whether any token exceeds the configured entropy threshold.
func matchEntropyTokens(text string) bool {
	dataImageRanges := findDataImageRanges(strings.ToLower(text))
	for _, loc := range highEntropyTokenPattern.FindAllStringIndex(text, -1) {
		if indexInRanges(loc[0], dataImageRanges) {
			continue
		}
		tok := text[loc[0]:loc[1]]
		if shannonEntropy(tok) > secretsEntropyThreshold {
			return true
		}
	}
	return false
}

// buildSecretsResult constructs the final secrets result from detector outputs.
func buildSecretsResult(high []string, medium []string, hasEntropy bool) secretsResult {
	result := secretsResult{Confidence: "low"}
	if len(high) == 0 && len(medium) == 0 && !hasEntropy {
		return result
	}

	seen := make(map[string]struct{}, len(high)+len(medium)+1)
	for _, t := range high {
		seen[t] = struct{}{}
	}
	for _, t := range medium {
		if t == secretsEntropyKeywordContextType {
			continue
		}
		seen[t] = struct{}{}
	}
	if hasEntropy {
		seen["high-entropy-token"] = struct{}{}
	}

	result.HasSecrets = true
	result.MatchedTypes = mapKeysSorted(seen)

	switch {
	case len(high) > 0:
		result.Confidence = "high"
	case hasMediumConfidenceTypes(medium):
		result.Confidence = "medium"
	case hasEntropy && hasEntropyKeywordContext(medium):
		result.Confidence = "medium"
	default:
		result.Confidence = "low"
	}

	return result
}

// hasMediumConfidenceTypes reports whether medium detector returned actual medium matches.
func hasMediumConfidenceTypes(medium []string) bool {
	for _, t := range medium {
		if t != secretsEntropyKeywordContextType {
			return true
		}
	}
	return false
}

// hasEntropyKeywordContext reports whether entropy had secret-keyword context.
func hasEntropyKeywordContext(medium []string) bool {
	for _, t := range medium {
		if t == secretsEntropyKeywordContextType {
			return true
		}
	}
	return false
}

// shannonEntropy returns the Shannon entropy score for a string token.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}

	freq := make(map[rune]int)
	total := 0
	for _, r := range s {
		freq[r]++
		total++
	}

	if total == 0 {
		return 0
	}

	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(total)
		entropy -= p * (math.Log(p) / math.Log(2))
	}

	return entropy
}

func findDataImageRanges(lowerText string) [][2]int {
	ranges := make([][2]int, 0)
	if lowerText == "" {
		return ranges
	}

	start := 0
	for {
		idx := strings.Index(lowerText[start:], "data:image")
		if idx < 0 {
			break
		}
		absStart := start + idx
		absEnd := len(lowerText)
		for i := absStart; i < len(lowerText); i++ {
			if lowerText[i] == ' ' || lowerText[i] == '\n' || lowerText[i] == '\r' || lowerText[i] == '\t' {
				absEnd = i
				break
			}
		}
		ranges = append(ranges, [2]int{absStart, absEnd})
		start = absEnd
		if start >= len(lowerText) {
			break
		}
	}

	return ranges
}

func indexInRanges(idx int, ranges [][2]int) bool {
	for _, r := range ranges {
		if idx >= r[0] && idx < r[1] {
			return true
		}
	}
	return false
}

func mapKeysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
