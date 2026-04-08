package engine

import "strings"

const (
	fullwidthASCIIRangeStart = 0xFF01
	fullwidthASCIIRangeEnd   = 0xFF5E
	fullwidthASCIIOffset     = 0xFEE0
	fullwidthSpaceRune       = 0x3000
)

// sanitizeCompatibilityFoldMap provides a stdlib-only fallback for common
// compatibility forms when full NFKC normalization is unavailable.
var sanitizeCompatibilityFoldMap = map[rune]string{
	'ﬁ': "fi",
	'ﬂ': "fl",
	'’': "'",
	'“': "\"",
	'”': "\"",
	'‐': "-",
	'‑': "-",
	'‒': "-",
	'–': "-",
	'—': "-",
}

// sanitizeHomoglyphMap maps common confusables to Latin lookalikes so
// regex-based detectors cannot be bypassed by mixed-script obfuscation.
var sanitizeHomoglyphMap = map[rune]string{
	'а': "a", 'А': "A", // Cyrillic a
	'е': "e", 'Е': "E", // Cyrillic e
	'о': "o", 'О': "O", // Cyrillic o
	'р': "p", 'Р': "P", // Cyrillic er
	'с': "c", 'С': "C", // Cyrillic es
	'у': "y", 'У': "Y", // Cyrillic u
	'х': "x", 'Х': "X", // Cyrillic ha
	'і': "i", 'І': "I", // Cyrillic i
	'ј': "j", 'Ј': "J", // Cyrillic je
	'ѕ': "s",           // Cyrillic dze
	'Α': "A", 'α': "a", // Greek alpha
	'Β': "B", 'β': "b", // Greek beta
	'Ε': "E", 'ε': "e", // Greek epsilon
	'Ι': "I", 'ι': "i", // Greek iota
	'Κ': "K", 'κ': "k", // Greek kappa
	'Μ': "M", 'μ': "m", // Greek mu
	'Ν': "N", 'ν': "v", // Greek nu (visual)
	'Ο': "O", 'ο': "o", // Greek omicron
	'Ρ': "P", 'ρ': "p", // Greek rho
	'Τ': "T", 'τ': "t", // Greek tau
	'Χ': "X", 'χ': "x", // Greek chi
}

func preprocessUnicodeForSanitize(text string) string {
	if text == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(text))

	for _, r := range text {
		if replacement, ok := sanitizeCompatibilityFoldMap[r]; ok {
			b.WriteString(replacement)
			continue
		}

		if r == fullwidthSpaceRune {
			b.WriteByte(' ')
			continue
		}
		if r >= fullwidthASCIIRangeStart && r <= fullwidthASCIIRangeEnd {
			b.WriteRune(r - fullwidthASCIIOffset)
			continue
		}

		if replacement, ok := sanitizeHomoglyphMap[r]; ok {
			b.WriteString(replacement)
			continue
		}

		b.WriteRune(r)
	}

	return b.String()
}
