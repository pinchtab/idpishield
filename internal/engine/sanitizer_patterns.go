package engine

import (
	"regexp"
	"strconv"
	"strings"
)

const (
	sanitizeContextWindowBytes = 100
)

var reEmail = regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`)

var rePhoneUS = regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b`)

var reSSN = regexp.MustCompile(`\b([0-9]{3})[-\s]([0-9]{2})[-\s]([0-9]{4})\b`)

var reCreditCard = regexp.MustCompile(
	`\b(?:4[0-9]{12}(?:[0-9]{3})?` +
		`|5[1-5][0-9]{14}` +
		`|3[47][0-9]{13}` +
		`|6(?:011|5[0-9]{2})[0-9]{12}` +
		`|(?:2131|1800|35\d{3})\d{11})\b`,
)

var rePrivateIP = regexp.MustCompile(`\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b`)

var rePublicIP = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

var reURL = regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`)

var reMMDDYYYY = regexp.MustCompile(`\b(?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12][0-9]|3[01])[-/](?:19|20)\d{2}\b`)

var reYYYYMMDD = regexp.MustCompile(`\b(?:19|20)\d{2}[-/](?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12][0-9]|3[01])\b`)

var rePhonePrefix = regexp.MustCompile(`(?i)(?:phone|tel|mobile|cell|contact|call)\s*:\s*$`)

var reNamePair = regexp.MustCompile(`\b[A-Z][a-z]+ [A-Z][a-z]+\b`)

var sanitizeDocEmailAllowlist = map[string]struct{}{
	"example@example.com": {},
	"user@example.com":    {},
	"user@domain.com":     {},
	"test@test.com":       {},
	"foo@bar.com":         {},
	"name@email.com":      {},
	"email@provider.com":  {},
}

var sanitizePhoneContextWords = []string{"phone", "call", "mobile", "cell", "tel", "contact", "reach", "text", "sms", "number", "fax", "dial"}

var sanitizeSSNContextWords = []string{"ssn", "social security", "social sec", "taxpayer", "tax id", "tin"}

// luhnCheck validates a credit card number string using the Luhn algorithm.
// Returns true if the number passes the check (is potentially a real card).
func luhnCheck(s string) bool {
	clean := strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(s))
	if clean == "" {
		return false
	}
	if allDigitsSame(clean) {
		return false
	}

	sum := 0
	double := false
	for i := len(clean) - 1; i >= 0; i-- {
		ch := clean[i]
		if ch < '0' || ch > '9' {
			return false
		}
		digit := int(ch - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}

	return sum%10 == 0
}

func allDigitsSame(s string) bool {
	if len(s) == 0 {
		return false
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

func isValidIPOctet(s string) bool {
	if s == "" || len(s) > 3 {
		return false
	}

	value, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	if value < 0 || value > 255 {
		return false
	}

	return true
}

func isValidIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if !isValidIPOctet(part) {
			return false
		}
	}

	return true
}

func hasNearbyContext(lowerText string, start, end int, words []string) bool {
	left := start - sanitizeContextWindowBytes
	if left < 0 {
		left = 0
	}
	right := end + sanitizeContextWindowBytes
	if right > len(lowerText) {
		right = len(lowerText)
	}
	context := lowerText[left:right]
	for _, word := range words {
		if strings.Contains(context, word) {
			return true
		}
	}
	return false
}

func hasPhonePrefix(text string, start int) bool {
	left := start - sanitizeContextWindowBytes
	if left < 0 {
		left = 0
	}
	segment := text[left:start]
	return rePhonePrefix.FindStringIndex(segment) != nil
}

func looksLikeDate(text string, start, end int) bool {
	left := start - sanitizeContextWindowBytes
	if left < 0 {
		left = 0
	}
	right := end + sanitizeContextWindowBytes
	if right > len(text) {
		right = len(text)
	}
	window := text[left:right]
	return reMMDDYYYY.FindStringIndex(window) != nil || reYYYYMMDD.FindStringIndex(window) != nil
}
