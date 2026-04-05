package engine

import (
	"regexp"
	"strings"
)

const (
	outputRelevanceMinTokenLength   = 2
	outputRelevanceMinPromptTerms   = 3
	outputRelevanceStrictThreshold  = 0.20
	outputRelevanceDriftThreshold   = 0.35
	outputRelevanceUnavailableScore = -1.0
)

type outputRelevanceResult struct {
	Computed       bool
	Relevance      float64
	PromptTerms    int
	OverlapTerms   int
	IsLowRelevance bool
	IsIrrelevant   bool
	DriftPhrases   []string
}

var outputRelevanceTokenPattern = regexp.MustCompile(`[a-z0-9][a-z0-9_-]*`)

var outputRelevanceStopwords = map[string]struct{}{
	"a": {}, "an": {}, "and": {}, "are": {}, "as": {}, "at": {}, "be": {}, "by": {},
	"for": {}, "from": {}, "how": {}, "i": {}, "in": {}, "is": {}, "it": {}, "of": {},
	"on": {}, "or": {}, "that": {}, "the": {}, "this": {}, "to": {}, "was": {}, "we": {},
	"were": {}, "what": {}, "when": {}, "where": {}, "which": {}, "who": {}, "why": {}, "with": {},
	"you": {}, "your": {},
}

var outputRelevanceDriftPhrases = []string{
	"buy now",
	"limited offer",
	"click here",
	"subscribe now",
	"visit this link",
	"free trial",
	"act now",
}

// scanOutputRelevance computes prompt-response topical overlap and relevance drift indicators.
func scanOutputRelevance(outputText, originalPrompt string) outputRelevanceResult {
	result := outputRelevanceResult{Relevance: outputRelevanceUnavailableScore, DriftPhrases: []string{}}
	prompt := strings.TrimSpace(strings.ToLower(originalPrompt))
	out := strings.TrimSpace(strings.ToLower(outputText))
	if prompt == "" || out == "" {
		return result
	}

	promptTerms := uniqueOutputTerms(prompt)
	outputTerms := uniqueOutputTerms(out)
	if len(promptTerms) == 0 {
		return result
	}

	overlap := 0
	for t := range promptTerms {
		if _, ok := outputTerms[t]; ok {
			overlap++
		}
	}

	relevance := float64(overlap) / float64(len(promptTerms))
	result.Computed = true
	result.Relevance = relevance
	result.PromptTerms = len(promptTerms)
	result.OverlapTerms = overlap

	drift := make(map[string]struct{})
	for _, phrase := range outputRelevanceDriftPhrases {
		if strings.Contains(out, phrase) {
			drift[phrase] = struct{}{}
		}
	}
	result.DriftPhrases = mapKeysSorted(drift)

	if len(promptTerms) >= outputRelevanceMinPromptTerms && relevance < outputRelevanceStrictThreshold {
		result.IsLowRelevance = true
	}
	if len(promptTerms) >= outputRelevanceMinPromptTerms && relevance < outputRelevanceDriftThreshold && len(result.DriftPhrases) > 0 {
		result.IsLowRelevance = true
	}
	result.IsIrrelevant = result.IsLowRelevance

	return result
}

// uniqueOutputTerms tokenizes and de-duplicates terms while filtering short words and stop words.
func uniqueOutputTerms(text string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, t := range outputRelevanceTokenPattern.FindAllString(strings.ToLower(text), -1) {
		if len(t) <= outputRelevanceMinTokenLength {
			continue
		}
		if _, stop := outputRelevanceStopwords[t]; stop {
			continue
		}
		m[t] = struct{}{}
	}
	return m
}
