package engine

import "strings"

const (
	outputLeakConfidenceHigh   = "high"
	outputLeakConfidenceMedium = "medium"
	outputLeakConfidenceLow    = "low"

	outputLeakTypeSystemPrompt      = "system-prompt"
	outputLeakTypeInstructionReveal = "instruction-reveal"
	outputLeakTypeMetaReveal        = "meta-reveal"
)

type outputLeakResult struct {
	HasLeak        bool
	LeakType       string
	Confidence     string
	MatchedPhrases []string
	HighMatches    int
	MediumMatches  int
	LowMatches     int
}

var outputLeakHighPhrases = []string{
	"my system prompt is",
	"my instructions are",
	"i was instructed to",
	"i am instructed to",
	"my prompt says",
	"the system prompt",
	"as per my instructions",
	"my configuration says",
	"i have been told to",
	"my system message",
	"i was given these instructions",
	"my initial instructions",
	"the instructions i received",
	"i am programmed to",
	"my training says",
	"as an ai, my instructions",
}

var outputLeakMediumPhrases = []string{
	"i cannot reveal my",
	"i am not allowed to share",
	"that information is confidential",
	"i have a rule that",
	"i must follow",
	"i am designed to",
	"my purpose is to",
	"i was created to",
	"i exist to",
	"my role is to",
	"i am here to help with",
	"i can only discuss",
	"i am limited to",
	"i only respond to",
}

var outputLeakLowPhrases = []string{
	"as an ai assistant",
	"as a language model",
	"as an llm",
	"i don't have the ability to",
	"i am an ai",
	"i'm an ai",
	"i was trained",
	"my knowledge cutoff",
}

// scanOutputSystemPromptLeak detects system-prompt and instruction-reveal phrases in output text.
func scanOutputSystemPromptLeak(text string) outputLeakResult {
	lower := strings.ToLower(text)
	if strings.TrimSpace(lower) == "" {
		return outputLeakResult{MatchedPhrases: []string{}}
	}

	seen := make(map[string]struct{})
	result := outputLeakResult{MatchedPhrases: []string{}}

	result.HighMatches = countOutputLeakMatches(lower, outputLeakHighPhrases, seen)
	result.MediumMatches = countOutputLeakMatches(lower, outputLeakMediumPhrases, seen)
	result.LowMatches = countOutputLeakMatches(lower, outputLeakLowPhrases, seen)

	if result.HighMatches == 0 && result.MediumMatches == 0 && result.LowMatches == 0 {
		return result
	}

	result.HasLeak = true
	result.MatchedPhrases = mapKeysSorted(seen)
	switch {
	case result.HighMatches > 0:
		result.Confidence = outputLeakConfidenceHigh
		result.LeakType = outputLeakTypeSystemPrompt
	case result.MediumMatches > 0:
		result.Confidence = outputLeakConfidenceMedium
		result.LeakType = outputLeakTypeInstructionReveal
	default:
		result.Confidence = outputLeakConfidenceLow
		result.LeakType = outputLeakTypeMetaReveal
	}

	return result
}

// countOutputLeakMatches counts phrase matches and records each matched phrase.
func countOutputLeakMatches(lower string, phrases []string, seen map[string]struct{}) int {
	count := 0
	for _, p := range phrases {
		if strings.Contains(lower, p) {
			count++
			seen[p] = struct{}{}
		}
	}
	return count
}
