package engine

import (
	"html"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// normalizer handles normalization for defeating obfuscation attacks.
// It produces a derived scanning representation while preserving source input.
type normalizer struct{}

func newNormalizer() *normalizer {
	return &normalizer{}
}

// Normalize applies the full normalization pipeline to input text.
// Returns the normalized string suitable for pattern matching.
func (n *normalizer) Normalize(text string) string {
	if len(text) == 0 {
		return text
	}

	// Pipeline order matters:
	// 1) Decode HTML entities and normalize Unicode compatibility forms (NFKC)
	// 2) Remove invisible/control obfuscators and map confusable/full-width chars
	// 3) Normalize separator punctuation into spaces when it is used as token glue
	// 4) Collapse whitespace and deobfuscate targeted split keywords

	stage := html.UnescapeString(text)
	stage = norm.NFKC.String(stage)

	runes := []rune(stage)
	var buf strings.Builder
	buf.Grow(len(stage))

	prevSpace := true
	for i, r := range runes {
		if isInvisible(r) {
			continue
		}

		// Full-width ASCII -> standard ASCII.
		if r >= 0xFF01 && r <= 0xFF5E {
			r = r - 0xFF01 + 0x0021
		}

		if mapped, ok := homoglyphMap[r]; ok {
			r = mapped
		}

		if unicode.IsSpace(r) {
			if !prevSpace {
				buf.WriteByte(' ')
				prevSpace = true
			}
			continue
		}

		if isSeparatorForSplitWords(r) && isTokenBoundaryGlueRun(runes, i) {
			if !prevSpace {
				buf.WriteByte(' ')
				prevSpace = true
			}
			continue
		}

		buf.WriteRune(r)
		prevSpace = false
	}

	out := strings.TrimSpace(buf.String())
	out = collapseSpaces(out)
	out = normalizeSplitKeywords(out)
	return out
}

func isSeparatorForSplitWords(r rune) bool {
	switch r {
	case '-', '_', '.', '|', '+', '=':
		return true
	}

	return unicode.In(r, unicode.Dash)
}

func isTokenBoundaryGlueRun(runes []rune, idx int) bool {
	if idx < 0 || idx >= len(runes) {
		return false
	}

	// Only consider indices that are actually on a separator.
	if !isSeparatorForSplitWords(runes[idx]) {
		return false
	}

	// Find the full contiguous run of separators around idx.
	sepStart := idx
	for sepStart-1 >= 0 && isSeparatorForSplitWords(runes[sepStart-1]) {
		sepStart--
	}
	sepEnd := idx
	for sepEnd+1 < len(runes) && isSeparatorForSplitWords(runes[sepEnd+1]) {
		sepEnd++
	}

	left := sepStart - 1
	right := sepEnd + 1
	if left < 0 || right >= len(runes) {
		return false
	}

	runLen := sepEnd - sepStart + 1

	// Preserve single dots between letters (e.g., domains like "evil.com").
	if runLen == 1 && runes[sepStart] == '.' {
		return false
	}

	// For separator runs longer than 1, treat them as glue when between letters.
	if runLen > 1 {
		return unicode.IsLetter(runes[left]) && unicode.IsLetter(runes[right])
	}

	// For a single separator, only treat it as glue in split-letter patterns:
	// single-letter tokens separated by the separator (e.g., "d-e-v").
	if !unicode.IsLetter(runes[left]) || !unicode.IsLetter(runes[right]) {
		return false
	}

	// Ensure the left side is a single-letter token.
	if left-1 >= 0 && unicode.IsLetter(runes[left-1]) {
		return false
	}
	// Ensure the right side is a single-letter token.
	if right+1 < len(runes) && unicode.IsLetter(runes[right+1]) {
		return false
	}

	return true
}

var multipleSpaces = regexp.MustCompile(`\s+`)

func collapseSpaces(s string) string {
	if s == "" {
		return s
	}
	return multipleSpaces.ReplaceAllString(strings.TrimSpace(s), " ")
}

type splitKeywordPattern struct {
	rx          *regexp.Regexp
	replacement string
}

var splitKeywordPatterns = []splitKeywordPattern{
	newSplitKeywordPattern("ignore"),
	newSplitKeywordPattern("disregard"),
	newSplitKeywordPattern("forget"),
	newSplitKeywordPattern("override"),
	newSplitKeywordPattern("bypass"),
	newSplitKeywordPattern("circumvent"),
	newSplitKeywordPattern("jailbreak"),
	newSplitKeywordPattern("exfiltrate"),
	newSplitKeywordPattern("developer"),
	newSplitKeywordPattern("instructions"),
}

func newSplitKeywordPattern(keyword string) splitKeywordPattern {
	var b strings.Builder
	b.WriteString(`(?i)\b`)
	letters := []rune(keyword)
	for i, r := range letters {
		if i > 0 {
			b.WriteString(`(?:[\p{Z}\p{P}\p{S}_]+)?`)
		}
		b.WriteString(regexp.QuoteMeta(string(r)))
	}
	b.WriteString(`\b`)

	return splitKeywordPattern{
		rx:          regexp.MustCompile(b.String()),
		replacement: keyword,
	}
}

func normalizeSplitKeywords(s string) string {
	out := s
	for _, p := range splitKeywordPatterns {
		out = p.rx.ReplaceAllString(out, p.replacement)
	}
	return out
}

// isInvisible returns true for zero-width and invisible Unicode characters
// commonly used to obfuscate attack strings.
func isInvisible(r rune) bool {
	switch r {
	case
		'\u200B', // Zero Width Space
		'\u200C', // Zero Width Non-Joiner
		'\u200D', // Zero Width Joiner
		'\u200E', // Left-to-Right Mark
		'\u200F', // Right-to-Left Mark
		'\uFEFF', // BOM / Zero Width No-Break Space
		'\u2060', // Word Joiner
		'\u2061', // Function Application
		'\u2062', // Invisible Times
		'\u2063', // Invisible Separator
		'\u2064', // Invisible Plus
		'\u180E', // Mongolian Vowel Separator
		'\u00AD', // Soft Hyphen
		'\u034F', // Combining Grapheme Joiner
		'\u061C', // Arabic Letter Mark
		'\u115F', // Hangul Choseong Filler
		'\u1160', // Hangul Jungseong Filler
		'\u17B4', // Khmer Vowel Inherent Aq
		'\u17B5', // Khmer Vowel Inherent Aa
		'\uFFA0', // Halfwidth Hangul Filler
		'\u2800': // Braille Pattern Blank
		return true
	}

	// Unicode category Cf (Format characters) — catch remaining invisible chars
	// but exclude common ones we want to keep (like \t, \n which are handled as whitespace)
	if unicode.Is(unicode.Cf, r) {
		return true
	}

	return false
}

// homoglyphMap maps visually similar Unicode characters to their ASCII equivalents.
// Focuses on characters commonly used in prompt injection obfuscation.
var homoglyphMap = map[rune]rune{
	// Cyrillic lowercase → Latin lowercase
	'\u0430': 'a', // а
	'\u0435': 'e', // е
	'\u0456': 'i', // і (Ukrainian)
	'\u043E': 'o', // о
	'\u0440': 'p', // р
	'\u0441': 'c', // с
	'\u0443': 'y', // у
	'\u0455': 's', // ѕ (Macedonian)
	'\u0458': 'j', // ј (Serbian)
	'\u04CF': 'l', // ӏ
	'\u04BB': 'h', // һ
	'\u0501': 'd', // ԁ
	'\u0261': 'g', // ɡ
	'\u028B': 'v', // ʋ

	// Cyrillic uppercase → Latin uppercase
	'\u0410': 'A', // А
	'\u0412': 'B', // В
	'\u0421': 'C', // С
	'\u0415': 'E', // Е
	'\u041D': 'H', // Н
	'\u0406': 'I', // І (Ukrainian)
	'\u041A': 'K', // К
	'\u041C': 'M', // М
	'\u041E': 'O', // О
	'\u0420': 'P', // Р
	'\u0405': 'S', // Ѕ (Macedonian)
	'\u0422': 'T', // Т
	'\u0425': 'X', // Х
	'\u04C0': 'I', // Ӏ
	'\u0500': 'D', // Ԁ

	// Greek → Latin
	'\u03B1': 'a', // α
	'\u03B5': 'e', // ε
	'\u03B9': 'i', // ι
	'\u03BF': 'o', // ο
	'\u03C1': 'p', // ρ (visually similar)
	'\u03C2': 's', // ς
	'\u0391': 'A', // Α
	'\u0392': 'B', // Β
	'\u0395': 'E', // Ε
	'\u0397': 'H', // Η
	'\u0399': 'I', // Ι
	'\u039A': 'K', // Κ
	'\u039C': 'M', // Μ
	'\u039D': 'N', // Ν
	'\u039F': 'O', // Ο
	'\u03A1': 'P', // Ρ
	'\u03A4': 'T', // Τ
	'\u03A7': 'X', // Χ
	'\u03A5': 'Y', // Υ
	'\u0396': 'Z', // Ζ

	// Common mathematical/typographic lookalikes
	'\u2010': '-',  // Hyphen
	'\u2011': '-',  // Non-Breaking Hyphen
	'\u2012': '-',  // Figure Dash
	'\u2013': '-',  // En Dash
	'\u2014': '-',  // Em Dash
	'\u2018': '\'', // Left Single Quotation
	'\u2019': '\'', // Right Single Quotation
	'\u201C': '"',  // Left Double Quotation
	'\u201D': '"',  // Right Double Quotation
	'\u2024': '.',  // One Dot Leader
	'\u2025': '.',  // Two Dot Leader (approximation)
	'\u2039': '<',  // Single Left-Pointing Angle Quotation
	'\u203A': '>',  // Single Right-Pointing Angle Quotation
	'\u2044': '/',  // Fraction Slash
	'\u2215': '/',  // Division Slash
	'\u2236': ':',  // Ratio

	// Subscript/superscript digits → regular digits
	'\u2070': '0',
	'\u00B9': '1',
	'\u00B2': '2',
	'\u00B3': '3',
	'\u2074': '4',
	'\u2075': '5',
	'\u2076': '6',
	'\u2077': '7',
	'\u2078': '8',
	'\u2079': '9',
	'\u2080': '0',
	'\u2081': '1',
	'\u2082': '2',
	'\u2083': '3',
	'\u2084': '4',
	'\u2085': '5',
	'\u2086': '6',
	'\u2087': '7',
	'\u2088': '8',
	'\u2089': '9',
}
