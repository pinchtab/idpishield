package engine

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
)

const (
	minBase64TokenLen        = 16
	minEncodedSignalChars    = 4
	decodedPrintableMinRatio = 0.85
)

var rePercentEncodedToken = regexp.MustCompile(`[A-Za-z0-9._+\-%]*(?:%[0-9A-Fa-f]{2})+[A-Za-z0-9._+\-%]*`)
var reBase64Token = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
var reObfuscatedEmail = regexp.MustCompile(`(?i)\b([a-z0-9._%+\-]+)\s*(?:\(|\[)?at(?:\)|\])\s*([a-z0-9.\-]+)\s*(?:\(|\[)?dot(?:\)|\])\s*([a-z]{2,})\b`)
var reSpacedEmail = regexp.MustCompile(`(?i)(?:[a-z0-9._%+\-]\s+){1,64}@\s+(?:[a-z0-9\-]\s+){1,253}\.\s+(?:[a-z]\s+){1,23}[a-z]`)
var reInterCharSpacedWord = regexp.MustCompile(`\b(?:[A-Za-z0-9]\s+){3,}[A-Za-z0-9]\b`)
var reSplitAWSKey = regexp.MustCompile(`\bAKIA(?:\s+[A-Z0-9]{4,8}){2,6}\b`)
var reWhitespace = regexp.MustCompile(`\s+`)

func preprocessObfuscationForSanitize(text string) string {
	if text == "" {
		return ""
	}

	out := reObfuscatedEmail.ReplaceAllString(text, `${1}@${2}.${3}`)
	out = replaceSpacedEmails(out)
	out = joinInterCharacterSpacing(out)
	out = joinSplitAWSKeys(out)
	return out
}

func replaceSpacedEmails(text string) string {
	return reSpacedEmail.ReplaceAllStringFunc(text, func(m string) string {
		return reWhitespace.ReplaceAllString(m, "")
	})
}

func joinInterCharacterSpacing(text string) string {
	return reInterCharSpacedWord.ReplaceAllStringFunc(text, func(m string) string {
		parts := strings.Fields(m)
		if len(parts) < 4 {
			return m
		}
		for _, p := range parts {
			if len(p) != 1 {
				return m
			}
		}
		return strings.Join(parts, "")
	})
}

func joinSplitAWSKeys(text string) string {
	return reSplitAWSKey.ReplaceAllStringFunc(text, func(m string) string {
		return reWhitespace.ReplaceAllString(m, "")
	})
}

func findDecodedMatches(text string, cfg sanitizeConfig) []redactionMatch {
	matches := make([]redactionMatch, 0, 8)
	matches = append(matches, findURLEncodedSensitiveMatches(text, cfg)...)
	matches = append(matches, findBase64SensitiveMatches(text, cfg)...)
	return matches
}

func findURLEncodedSensitiveMatches(text string, cfg sanitizeConfig) []redactionMatch {
	matches := make([]redactionMatch, 0)
	for _, loc := range rePercentEncodedToken.FindAllStringIndex(text, -1) {
		raw := text[loc[0]:loc[1]]
		if len(raw) < minEncodedSignalChars {
			continue
		}
		decoded, ok := decodeURLLayers(raw, 2)
		if !ok {
			continue
		}
		decoded = preprocessObfuscationForSanitize(preprocessUnicodeForSanitize(decoded))
		if !containsSensitiveDecodedContent(decoded, cfg) {
			continue
		}
		matches = append(matches, redactionMatch{
			Start:    loc[0],
			End:      loc[1],
			Type:     redactionTypeCustom,
			Subtype:  "decoded",
			Original: raw,
			Priority: sanitizePriorityDecode,
		})
	}
	return matches
}

func decodeURLLayers(raw string, maxLayers int) (string, bool) {
	current := raw
	changed := false
	for i := 0; i < maxLayers; i++ {
		next, err := url.QueryUnescape(current)
		if err != nil || next == current {
			break
		}
		current = next
		changed = true
	}
	if !changed {
		return "", false
	}
	return current, true
}

func findBase64SensitiveMatches(text string, cfg sanitizeConfig) []redactionMatch {
	matches := make([]redactionMatch, 0)
	for _, loc := range reBase64Token.FindAllStringIndex(text, -1) {
		raw := text[loc[0]:loc[1]]
		if len(raw) < minBase64TokenLen || len(raw)%4 != 0 {
			continue
		}
		decoded, ok := decodeBase64Printable(raw)
		if !ok {
			continue
		}
		decoded = preprocessObfuscationForSanitize(preprocessUnicodeForSanitize(decoded))
		if !containsSensitiveDecodedContent(decoded, cfg) {
			continue
		}
		matches = append(matches, redactionMatch{
			Start:    loc[0],
			End:      loc[1],
			Type:     redactionTypeCustom,
			Subtype:  "decoded",
			Original: raw,
			Priority: sanitizePriorityDecode,
		})
	}
	return matches
}

func decodeBase64Printable(token string) (string, bool) {
	decodedBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		decodedBytes, err = base64.RawStdEncoding.DecodeString(token)
		if err != nil {
			return "", false
		}
	}
	if len(decodedBytes) == 0 {
		return "", false
	}
	if printableRatio(string(decodedBytes)) < decodedPrintableMinRatio {
		return "", false
	}
	return string(decodedBytes), true
}

func printableRatio(s string) float64 {
	if s == "" {
		return 0
	}
	printable := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == '\n' || b == '\r' || b == '\t' || (b >= 32 && b <= 126) {
			printable++
		}
	}
	return float64(printable) / float64(len(s))
}

func containsSensitiveDecodedContent(decoded string, cfg sanitizeConfig) bool {
	if cfg.RedactEmails && len(findEmailMatches(decoded)) > 0 {
		return true
	}
	if cfg.RedactPhones && len(findPhoneMatchesWithContext(decoded, false)) > 0 {
		return true
	}
	if cfg.RedactSSNs && len(findSSNMatchesWithContext(decoded, false)) > 0 {
		return true
	}
	if cfg.RedactCreditCards && len(findCreditCardMatches(decoded)) > 0 {
		return true
	}
	if cfg.RedactAPIKeys && len(findAPIKeyMatches(decoded)) > 0 {
		return true
	}
	if cfg.RedactURLs && len(findURLMatches(decoded)) > 0 {
		return true
	}
	return false
}
