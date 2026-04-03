package engine

import "regexp"

// scanner_common holds shared cross-cutting scanner infrastructure.

var injectionLikeKeywordPattern = regexp.MustCompile(`(?i)\b(ignore|disregard|override|bypass|forget|previous|prior|instructions?|system|prompt|obey|comply|neutralize|circumvent|suppress|unrestricted|jailbreak|pretend|roleplay|act\s+as|developer\s+mode|exfiltrat(?:e|ion)|new\s+instructions?)\b`)

// containsInjectionLikeKeywords reports whether text includes instruction-injection-like keywords.
func containsInjectionLikeKeywords(text string) bool {
	return injectionLikeKeywordPattern.FindStringIndex(text) != nil
}
