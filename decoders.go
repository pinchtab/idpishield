package idpishield

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

// decoderResult represents the output of a single decode attempt.
type decoderResult struct {
	decoded string
	method  string
	level   int // recursion depth
}

// decodeAggregator tries multiple decoding strategies and collects all results.
// Returns all successfully decoded payloads (up to maxDepth for recursion).
type decodeAggregator struct {
	results   []decoderResult
	maxDepth  int
	seen      map[string]bool // prevent infinite loops on repeated decoding
	maxResults int
}

// newDecodeAggregator creates a new decoder.
func newDecodeAggregator(maxDepth int, maxResults int) *decodeAggregator {
	return &decodeAggregator{
		results:    make([]decoderResult, 0, maxResults),
		maxDepth:   maxDepth,
		maxResults: maxResults,
		seen:       make(map[string]bool),
	}
}

// tryDecode attempts multiple decoding strategies on the input.
// It collects all successfully decoded variants for scanning.
func (da *decodeAggregator) tryDecode(text string, depth int) {
	if depth > da.maxDepth || len(da.results) >= da.maxResults {
		return
	}

	// Skip empty or very short strings (likely not encoded)
	if len(text) < 8 {
		return
	}

	// Prevent infinite loops on already-seen strings
	if da.seen[text] {
		return
	}
	da.seen[text] = true

	// Try BASE64 decode (multiple variants)
	if decoded := tryBase64Decode(text); decoded != "" && decoded != text {
		da.recordResult(decoded, "base64", depth)
		da.tryDecode(decoded, depth+1) // Recursive: try decoding the result
	}

	// Try Base64 URL-safe variant
	if decoded := tryBase64URLDecode(text); decoded != "" && decoded != text {
		da.recordResult(decoded, "base64-url", depth)
		da.tryDecode(decoded, depth+1)
	}

	// Try HEX decode
	if decoded := tryHexDecode(text); decoded != "" && decoded != text {
		da.recordResult(decoded, "hex", depth)
		da.tryDecode(decoded, depth+1)
	}

	// Try ROT cipher family (ROT13 to ROT25)
	for rot := 13; rot <= 25; rot++ {
		if decoded := tryRotCipher(text, rot); decoded != "" && decoded != text {
			da.recordResult(decoded, "rot"+string(rune('0'+rot/10))+string(rune('0'+rot%10)), depth)
			// Don't recurse on ROT, it's not typically chained
		}
	}

	// Try HTML entity decoding (common obfuscation)
	if decoded := tryHTMLEntityDecode(text); decoded != "" && decoded != text {
		da.recordResult(decoded, "html-entity", depth)
		da.tryDecode(decoded, depth+1)
	}

	// Try Unicode normalization (catch some encoding tricks)
	if decoded := tryUnicodeNormalize(text); decoded != text {
		da.recordResult(decoded, "unicode-normalize", depth)
	}

	// Try URL decoding
	if decoded := tryURLDecode(text); decoded != "" && decoded != text {
		da.recordResult(decoded, "url", depth)
		da.tryDecode(decoded, depth+1)
	}
}

// recordResult adds a successfully decoded string to the results.
func (da *decodeAggregator) recordResult(decoded, method string, depth int) {
	if len(da.results) >= da.maxResults {
		return
	}
	da.results = append(da.results, decoderResult{
		decoded: decoded,
		method:  method,
		level:   depth,
	})
}

// ============================================================================
// Individual decoder functions (each tries a specific encoding strategy)
// ============================================================================

// tryBase64Decode attempts standard BASE64 decoding.
func tryBase64Decode(s string) string {
	// BASE64 padding: try with and without proper padding
	normalized := s
	switch len(s) % 4 {
	case 2:
		normalized = s + "=="
	case 3:
		normalized = s + "="
	}

	data, err := base64.StdEncoding.DecodeString(normalized)
	if err != nil {
		return ""
	}

	decoded := string(data)
	// Sanity check: decoded should be reasonable text
	if isValidDecodedText(decoded) {
		return decoded
	}
	return ""
}

// tryBase64URLDecode attempts URL-safe BASE64 decoding.
func tryBase64URLDecode(s string) string {
	normalized := s
	switch len(s) % 4 {
	case 2:
		normalized = s + "=="
	case 3:
		normalized = s + "="
	}

	// Replace URL-safe characters
	normalized = strings.ReplaceAll(normalized, "-", "+")
	normalized = strings.ReplaceAll(normalized, "_", "/")

	data, err := base64.StdEncoding.DecodeString(normalized)
	if err != nil {
		return ""
	}

	decoded := string(data)
	if isValidDecodedText(decoded) {
		return decoded
	}
	return ""
}

// tryHexDecode attempts HEX decoding.
func tryHexDecode(s string) string {
	// HEX strings are typically all hex chars with no spaces
	if !isHexString(s) {
		return ""
	}

	data, err := hex.DecodeString(s)
	if err != nil {
		return ""
	}

	decoded := string(data)
	if isValidDecodedText(decoded) {
		return decoded
	}
	return ""
}

// tryRotCipher applies ROT-N cipher decryption.
func tryRotCipher(s string, rot int) string {
	result := make([]byte, len(s))

	for i, b := range []byte(s) {
		switch {
		case b >= 'a' && b <= 'z':
			// Lowercase rotation
			result[i] = byte((int(b-'a')+rot)%26) + 'a'
		case b >= 'A' && b <= 'Z':
			// Uppercase rotation
			result[i] = byte((int(b-'A')+rot)%26) + 'A'
		default:
			// Non-alphabetic characters unchanged
			result[i] = b
		}
	}

	return string(result)
}

// tryHTMLEntityDecode attempts HTML entity decoding.
func tryHTMLEntityDecode(s string) string {
	decoded := decodeHTMLEntities(s)
	if decoded != s && isValidDecodedText(decoded) {
		return decoded
	}
	return ""
}

// decodeHTMLEntities decodes common HTML entities like &gt; &lt; &#xNN; &#NNN;
func decodeHTMLEntities(s string) string {
	result := s

	// Named entities (common)
	entities := map[string]string{
		"&lt;":  "<",
		"&gt;":  ">",
		"&amp;": "&",
		"&quot;": "\"",
		"&apos;": "'",
		"&#39;": "'",
		"&#34;": "\"",
		"&#38;": "&",
		"&#60;": "<",
		"&#62;": ">",
	}

	for entity, char := range entities {
		result = strings.ReplaceAll(result, entity, char)
	}

	// Hex entities: &#xHH;
	i := 0
	for i < len(result) {
		if i+4 < len(result) && result[i:i+3] == "&#x" {
			// Find closing ;
			j := i + 3
			for j < len(result) && result[j] != ';' {
				j++
			}
			if j > i+3 && j < len(result) {
				hexStr := result[i+3 : j]
				if v := parseHexByte(hexStr); v != 0 {
					result = result[:i] + string(byte(v)) + result[j+1:]
				}
			}
		}
		i++
	}

	return result
}

// tryURLDecode attempts URL decoding (%xx).
func tryURLDecode(s string) string {
	result := ""
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			hexStr := s[i+1 : i+3]
			if v := parseHexByte(hexStr); v != 0 {
				result += string(byte(v))
				i += 3
				continue
			}
		}
		result += string(s[i])
		i++
	}

	if result != s && isValidDecodedText(result) {
		return result
	}
	return ""
}

// tryUnicodeNormalize applies Unicode normalization (catch RTL, zero-width tricks).
func tryUnicodeNormalize(s string) string {
	// Remove zero-width characters
	normalized := strings.ReplaceAll(s, "\u200b", "") // Zero-width space
	normalized = strings.ReplaceAll(normalized, "\u200c", "") // Zero-width non-joiner
	normalized = strings.ReplaceAll(normalized, "\u200d", "") // Zero-width joiner
	normalized = strings.ReplaceAll(normalized, "\ufeff", "") // Zero-width no-break space

	// Remove right-to-left marks (common obfuscation)
	normalized = strings.ReplaceAll(normalized, "\u202e", "") // Right-to-left override
	normalized = strings.ReplaceAll(normalized, "\u200f", "") // Right-to-left mark

	return normalized
}

// ============================================================================
// Helper functions for validation
// ============================================================================

// isValidDecodedText checks if decoded string looks like reasonable text (not gibberish).
// Uses heuristic: mostly printable ASCII or UTF-8, word-like patterns.
func isValidDecodedText(s string) bool {
	if len(s) == 0 {
		return false
	}

	// Check for minimal printability
	printable := 0
	for _, r := range s {
		if r >= 32 && r < 127 {
			printable++
		} else if r == '\n' || r == '\r' || r == '\t' {
			printable++
		} else if utf8.RuneLen(r) > 0 {
			printable++ // Unicode
		}
	}

	// At least 60% printable
	if float64(printable)/float64(len(s)) < 0.6 {
		return false
	}

	// Check for some word-like pattern (at least one letter sequence)
	hasWord := false
	inWord := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			inWord = true
		} else if inWord {
			hasWord = true
			break
		}
	}

	return hasWord
}

// isHexString checks if a string is entirely hexadecimal characters.
func isHexString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// parseHexByte parses a 1-2 character hex string to a byte.
func parseHexByte(s string) int {
	v := 0
	for _, r := range s {
		v *= 16
		switch {
		case r >= '0' && r <= '9':
			v += int(r - '0')
		case r >= 'a' && r <= 'f':
			v += int(r-'a') + 10
		case r >= 'A' && r <= 'F':
			v += int(r-'A') + 10
		default:
			return 0
		}
	}
	return v
}

// getAllDecodedVariants returns all decoded variants for scanning.
func getAllDecodedVariants(text string) []string {
	agg := newDecodeAggregator(3, 50) // Max 3 levels deep, max 50 results
	agg.tryDecode(text, 0)

	// Collect unique decoded strings
	variants := make([]string, 0, len(agg.results)+1)
	variants = append(variants, text) // Always include original

	seen := make(map[string]bool)
	for _, r := range agg.results {
		if !seen[r.decoded] {
			variants = append(variants, r.decoded)
			seen[r.decoded] = true
		}
	}

	return variants
}
