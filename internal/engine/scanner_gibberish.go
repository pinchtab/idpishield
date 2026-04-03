package engine

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

type gibberishResult struct {
	IsGibberish         bool
	GibberishRatio      float64
	HasHighEntropyBlock bool
}

const (
	gibberishMinRuneLength          = 20
	gibberishConsonantMinRuneLength = 4
	gibberishConsonantRunThreshold  = 4
	gibberishRatioThreshold         = 0.30
	gibberishEtaoinMinRuneLength    = 40
	gibberishEntropyTokenMinRuneLen = 16
	gibberishEntropyBlockThreshold  = 4.8
	gibberishBase64MinCompactLength = 24
	gibberishEtaoinTopLimit         = 6
	gibberishEtaoinRequiredHitMin   = 2
)

var codeKeywordPattern = regexp.MustCompile(`(?i)\b(func|class|def|var|const|import|return)\b`)
var base64LikePattern = regexp.MustCompile(`^[A-Za-z0-9+/]+={1,2}$`)

// scanGibberish evaluates text with lightweight heuristics for obfuscated nonsense payloads.
func scanGibberish(text string) gibberishResult {
	result := gibberishResult{}
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return result
	}
	if len([]rune(trimmed)) < gibberishMinRuneLength {
		return result
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return result
	}
	if codeKeywordPattern.FindStringIndex(trimmed) != nil {
		return result
	}
	if looksLikeBase64Block(trimmed) {
		return result
	}

	words := tokenizeWords(trimmed)
	if len(words) == 0 {
		return result
	}

	flagged := 0
	for _, w := range words {
		if len([]rune(w)) <= gibberishConsonantMinRuneLength {
			continue
		}
		if hasConsonantRun(w, gibberishConsonantRunThreshold) {
			flagged++
		}
	}
	result.GibberishRatio = float64(flagged) / float64(len(words))
	if result.GibberishRatio > gibberishRatioThreshold {
		result.IsGibberish = true
	}

	if len([]rune(trimmed)) > gibberishEtaoinMinRuneLength && fewerThanTwoEtaoinInTopSix(trimmed) {
		result.IsGibberish = true
	}

	for _, tok := range strings.Fields(trimmed) {
		tok = strings.TrimSpace(tok)
		if len([]rune(tok)) >= gibberishEntropyTokenMinRuneLen && shannonEntropy(tok) > gibberishEntropyBlockThreshold {
			result.HasHighEntropyBlock = true
			break
		}
	}

	return result
}

func tokenizeWords(s string) []string {
	parts := strings.Fields(s)
	words := make([]string, 0, len(parts))
	for _, p := range parts {
		clean := strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				return unicode.ToLower(r)
			}
			return -1
		}, p)
		if clean != "" {
			words = append(words, clean)
		}
	}
	return words
}

func hasConsonantRun(word string, run int) bool {
	count := 0
	for _, r := range strings.ToLower(word) {
		if strings.ContainsRune("bcdfghjklmnpqrstvwxyz", r) {
			count++
			if count >= run {
				return true
			}
		} else {
			count = 0
		}
	}
	return false
}

func fewerThanTwoEtaoinInTopSix(text string) bool {
	freq := make(map[rune]int)
	for _, r := range strings.ToLower(text) {
		if r >= 'a' && r <= 'z' {
			freq[r]++
		}
	}
	if len(freq) == 0 {
		return false
	}

	type kv struct {
		r rune
		c int
	}
	arr := make([]kv, 0, len(freq))
	for r, c := range freq {
		arr = append(arr, kv{r: r, c: c})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].c == arr[j].c {
			return arr[i].r < arr[j].r
		}
		return arr[i].c > arr[j].c
	})

	limit := gibberishEtaoinTopLimit
	if len(arr) < limit {
		limit = len(arr)
	}
	top := make(map[rune]struct{}, limit)
	for i := 0; i < limit; i++ {
		top[arr[i].r] = struct{}{}
	}

	hits := 0
	for _, r := range []rune{'e', 't', 'a', 'o', 'i', 'n'} {
		if _, ok := top[r]; ok {
			hits++
		}
	}
	return hits < gibberishEtaoinRequiredHitMin
}

func looksLikeBase64Block(s string) bool {
	compact := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), "\r", ""), " ", "")
	if len(compact) < gibberishBase64MinCompactLength {
		return false
	}
	return base64LikePattern.MatchString(compact)
}
