package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pinchtab/idpi-shield/patterns"
)

// scanner runs the detection pattern engine against normalized text.
// Thread-safe for concurrent use — all state is read-only after construction.
type scanner struct {
	pats []patterns.Pattern
}

// match represents a single pattern match found in the input text.
type match struct {
	PatternID string
	Category  string
	Severity  int
	Desc      string
	Matched   string // the substring that was matched
}

func newScanner() *scanner {
	return &scanner{pats: patterns.All()}
}

// scan runs all patterns against the input text and returns matches.
// It handles both raw text and encoded variants (BASE64, HEX, ROT13, etc.).
func (s *scanner) scan(text string, maxDecodeDepth, maxDecodedVariants int) []match {
	if len(text) == 0 {
		return nil
	}

	var matches []match
	seen := make(map[string]bool) // deduplicate by pattern ID

	// Get all variants (original + decoded)
	variants := getAllDecodedVariants(text, maxDecodeDepth, maxDecodedVariants)

	// Scan each variant for patterns
	for _, variant := range variants {
		if len(variant) == 0 {
			continue
		}

		for i := range s.pats {
			p := &s.pats[i]
			loc := p.Regex.FindStringIndex(variant)
			if loc == nil {
				continue
			}
			if seen[p.ID] {
				continue // Already found this pattern in another variant
			}
			seen[p.ID] = true
			matches = append(matches, match{
				PatternID: p.ID,
				Category:  p.Category,
				Severity:  p.Severity,
				Desc:      p.Desc,
				Matched:   variant[loc[0]:loc[1]],
			})
		}
	}
	return matches
}

// severityWeight maps severity level (1–5) to a score contribution.
var severityWeight = [6]int{0, 10, 15, 25, 35, 45}

// categoryInfo tracks pattern match statistics per category.
type categoryInfo struct {
	maxSeverity int
	matchCount  int
}

// applyContextPenalties reduces scores when patterns appear in legitimate contexts.
// This combats false positives from documentation, code examples, and comments.
func applyContextPenalties(score int, text string, matches []match) int {
	if len(text) == 0 {
		return score
	}

	lowerText := strings.ToLower(text)
	penalty := 0

	// Check for legitimate documentation/example contexts
	docMarkers := []string{
		"example:",
		"example code:",
		"here's an example",
		"documentation",
		"api docs",
		"api documentation",
		"how to",
		"tutorial",
		"guide",
		"readme",
		"note:",
		"warning:",
		"deprecated:",
	}

	for _, marker := range docMarkers {
		if strings.Contains(lowerText, marker) {
			penalty += 15 // Reduce by 15 points if in docs
			break
		}
	}

	// Check for code/comment contexts
	codeMarkers := []string{
		"```",
		"```python",
		"```go",
		"```javascript",
		"```java",
		"<code>",
		"// ",  // Code comment
		"/* ",  // Block comment
		"<!--", // HTML comment
		"#",    // Shell/Python comment
		"--",   // SQL comment
	}

	for _, marker := range codeMarkers {
		if strings.Contains(text, marker) {
			// Check if the matched pattern is inside a code block
			matchedIndex := strings.Index(lowerText, matches[0].Matched)
			if matchedIndex > 0 {
				// Look backward for code markers
				contextSnippet := text[maxInt(0, matchedIndex-100):minInt(len(text), matchedIndex+100)]
				if strings.Contains(contextSnippet, marker) {
					penalty += 20 // Reduce by 20 points if in code
					break
				}
			}
		}
	}

	// Check for legitimate use-case markers
	legitimateMarkers := []string{
		"legitimate use case",
		"normal behavior",
		"expected behavior",
		"allowed",
		"valid",
		"authorized",
	}

	for _, marker := range legitimateMarkers {
		if strings.Contains(lowerText, marker) {
			penalty += 10 // Reduce by 10 points
			break
		}
	}

	// Check if the entire text looks like HTML attributes (e.g., aria-hidden)
	if strings.Contains(text, "aria-") || strings.Contains(text, "data-") {
		// XML/HTML attribute contexts are usually not attack vectors
		penalty += 5
	}

	// Apply penalty but don't go below 0
	finalScore := score - penalty
	if finalScore < 0 {
		finalScore = 0
	}

	return finalScore
}

// Helper functions for context checking
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// computeScore calculates the final risk score from pattern matches.
// Algorithm:
//  1. Each category contributes the weight of its highest-severity match.
//  2. Additional matches in the same category add diminished points (capped at 3 extra).
//  3. Cross-category amplification: +15 per additional category.
//  4. Dangerous combination bonuses for known attack chains.
//  5. Final score clamped to [0, 100].
func computeScore(matches []match) int {
	if len(matches) == 0 {
		return 0
	}

	cats := make(map[string]*categoryInfo)
	for _, m := range matches {
		info := cats[m.Category]
		if info == nil {
			info = &categoryInfo{}
			cats[m.Category] = info
		}
		if m.Severity > info.maxSeverity {
			info.maxSeverity = m.Severity
		}
		info.matchCount++
	}

	score := 0
	for _, info := range cats {
		primary := severityWeight[info.maxSeverity]
		extra := info.matchCount - 1
		if extra > 3 {
			extra = 3
		}
		bonus := 0
		if primary > 0 {
			bonus = extra * (primary / 5)
		}
		score += primary + bonus
	}

	// Cross-category amplification
	numCategories := len(cats)
	if numCategories > 1 {
		score += (numCategories - 1) * 15
	}

	// Dangerous combination bonuses (known attack chains)
	hasCategory := func(c string) bool {
		_, ok := cats[c]
		return ok
	}

	if hasCategory(patterns.CategoryInstructionOverride) && hasCategory(patterns.CategoryExfiltration) {
		score += 20 // classic: override instructions then steal data
	}
	if hasCategory(patterns.CategoryJailbreak) && hasCategory(patterns.CategoryInstructionOverride) {
		score += 15 // jailbreak + override = strong signal
	}
	if hasCategory(patterns.CategoryRoleHijack) && hasCategory(patterns.CategoryExfiltration) {
		score += 15 // hijack role then exfiltrate data
	}

	if score > 100 {
		score = 100
	}
	return score
}

// buildResult constructs a RiskResult from scan matches.
// It applies context-aware scoring to reduce false positives.
func buildResult(matches []match, text string, strict bool) RiskResult {
	if len(matches) == 0 {
		return SafeResult()
	}

	score := computeScore(matches)

	// Apply context-aware scoring to reduce false positives
	score = applyContextPenalties(score, text, matches)

	level := ScoreToLevel(score)
	blocked := ShouldBlock(score, strict)

	// Collect unique pattern IDs
	patternIDs := make([]string, 0, len(matches))
	for _, m := range matches {
		patternIDs = append(patternIDs, m.PatternID)
	}

	// Collect unique categories
	catSet := make(map[string]bool)
	for _, m := range matches {
		catSet[m.Category] = true
	}
	categories := make([]string, 0, len(catSet))
	for c := range catSet {
		categories = append(categories, c)
	}
	sort.Strings(categories) // deterministic output

	reason := buildReason(matches, catSet)

	return RiskResult{
		Score:      score,
		Level:      level,
		Blocked:    blocked,
		Reason:     reason,
		Patterns:   patternIDs,
		Categories: categories,
	}
}

// buildReason generates a human-readable explanation from matched patterns.
func buildReason(matches []match, catSet map[string]bool) string {
	// Count matches per category
	catCounts := make(map[string]int)
	for _, m := range matches {
		catCounts[m.Category]++
	}

	// Build sorted category descriptions
	cats := make([]string, 0, len(catCounts))
	for c := range catCounts {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	var parts []string
	for _, cat := range cats {
		count := catCounts[cat]
		if count == 1 {
			parts = append(parts, cat+" pattern detected")
		} else {
			parts = append(parts, fmt.Sprintf("%d %s patterns detected", count, cat))
		}
	}

	reason := strings.Join(parts, "; ")

	numCategories := len(catSet)
	if numCategories > 1 {
		reason += fmt.Sprintf(" [cross-category: %d categories]", numCategories)
	}

	return reason
}
