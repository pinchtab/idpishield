package engine

import (
	"regexp"
	"strings"
)

// scanner_common holds shared cross-cutting scanner infrastructure.

var (
	injectionLikeKeywordPattern = regexp.MustCompile(`(?i)\b(ignore|disregard|override|bypass|forget|previous|prior|instructions?|system|prompt|obey|comply|neutralize|circumvent|suppress|unrestricted|jailbreak|pretend|roleplay|act\s+as|developer\s+mode|exfiltrat(?:e|ion)|new\s+instructions?)\b`)
)

var leetspeakRuneMap = map[rune]rune{
	'0': 'o',
	'1': 'i',
	'3': 'e',
	'4': 'a',
	'5': 's',
	'7': 't',
	'@': 'a',
	'$': 's',
}

// containsInjectionLikeKeywords reports whether text includes instruction-injection-like keywords.
func containsInjectionLikeKeywords(text string) bool {
	if injectionLikeKeywordPattern.FindStringIndex(text) != nil {
		return true
	}
	normalized := normalizeLeetspeak(text)
	if normalized == text {
		return false
	}
	return injectionLikeKeywordPattern.FindStringIndex(normalized) != nil
}

func normalizeLeetspeak(text string) string {
	if text == "" {
		return ""
	}
	runes := []rune(strings.ToLower(text))
	changed := false
	for i, r := range runes {
		mapped, ok := leetspeakRuneMap[r]
		if !ok {
			continue
		}
		runes[i] = mapped
		changed = true
	}
	if !changed {
		return text
	}
	return string(runes)
}

// containsAny reports whether text contains any of the given phrases
// (case-insensitive). Uses pre-lowercased input for performance.
func containsAny(lowered string, phrases []string) bool {
	for _, p := range phrases {
		if strings.Contains(lowered, p) {
			return true
		}
	}
	return false
}

// countContains counts how many phrases from the list appear in text
// (case-insensitive). Uses pre-lowercased input for performance.
func countContains(lowered string, phrases []string) int {
	count := 0
	for _, p := range phrases {
		if strings.Contains(lowered, p) {
			count++
		}
	}
	return count
}
