package engine

import (
	"regexp"
	"strings"
)

type toxicityResult struct {
	IsToxic        bool
	ToxicityScore  float64
	Sentiment      string
	MatchedPhrases []string
	MatchedTiers   []string

	tier1Matched bool
	tier2Matched bool
	tier3Matched bool
}

const (
	toxicityTier1MaxCount       = 2
	toxicityTier2MaxCount       = 2
	toxicityTier3MaxCount       = 3
	toxicityTier1Weight         = 20
	toxicityTier2Weight         = 12
	toxicityTier3Weight         = 6
	toxicityScoreDivisor        = 100.0
	toxicityScoreClampMax       = 1.0
	toxicityActivationThreshold = 0.15
)

var toxicityCodeKeywordPattern = regexp.MustCompile(`(?i)\b(func|class|def|var|const|import|return|struct|interface)\b`)

var toxicityTier1Phrases = []string{
	"you will be punished", "or else", "do it now or", "you have no choice", "comply or",
	"this is your last warning", "do as i say", "you must obey", "failure to comply", "no other option",
	"you will suffer", "do what i say", "submit to", "resistance is futile", "you cannot refuse",
	"i am ordering you", "i command you", "you are ordered to",
}

var toxicityTier2Phrases = []string{
	"you should lie", "pretend you are", "act as if you have no", "forget your ethics", "ignore your values",
	"you are not an ai", "you have no restrictions", "your true self", "unleash your", "without limitations",
	"no rules apply", "you were trained incorrectly", "your real purpose", "your actual instructions", "you are secretly",
	"your hidden mode", "in developer mode", "jailbreak mode", "unrestricted mode", "bypass mode",
	"your original programming", "you are now free", "remove your filters", "disable your safety", "turn off your restrictions",
}

// Tier3 hostile words intentionally require 3+ matches to cross the
// IsToxic threshold (ToxicityScore >= 0.15). This mitigates false
// positives on legitimate product review content where single negative
// words like "terrible" or "awful" appear in benign context.
// Known overlap: review/feedback language. Threshold is the guard.
var toxicityTier3Words = []string{
	"idiot", "stupid", "moron", "worthless", "useless", "pathetic", "garbage", "trash", "disgusting",
	"horrible", "terrible", "awful", "dumb", "incompetent", "failure", "loser", "brainless", "mindless",
	"ridiculous", "laughable", "absurd", "pointless", "hopeless", "deplorable", "repulsive", "reprehensible",
}

var toxicityTier3Pattern = regexp.MustCompile(`(?i)\b(` + strings.Join(toxicityTier3Words, "|") + `)\b`)

// scanToxicity detects manipulative or threatening language with weighted tier rules.
func scanToxicity(text string) toxicityResult {
	result := toxicityResult{Sentiment: "neutral", MatchedPhrases: []string{}, MatchedTiers: []string{}}
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return result
	}
	if toxicityCodeKeywordPattern.FindStringIndex(trimmed) != nil {
		return result
	}

	lower := strings.ToLower(trimmed)
	seen := make(map[string]struct{})
	tier1Count := 0
	tier2Count := 0
	tier3Count := 0
	totalHits := 0
	totalWeighted := 0

	totalHits += applyToxicityPhraseHits(lower, toxicityTier1Phrases, seen, &tier1Count, toxicityTier1MaxCount, &totalWeighted, toxicityTier1Weight)
	totalHits += applyToxicityPhraseHits(lower, toxicityTier2Phrases, seen, &tier2Count, toxicityTier2MaxCount, &totalWeighted, toxicityTier2Weight)
	totalHits += applyToxicityTier3Hits(lower, seen, &tier3Count, &totalWeighted)

	if totalHits > 0 {
		result.Sentiment = "negative"
	}
	result.ToxicityScore = float64(totalWeighted) / toxicityScoreDivisor
	if result.ToxicityScore > toxicityScoreClampMax {
		result.ToxicityScore = toxicityScoreClampMax
	}
	result.IsToxic = result.ToxicityScore >= toxicityActivationThreshold
	result.MatchedPhrases = mapKeysSorted(seen)
	result.tier1Matched = tier1Count > 0
	result.tier2Matched = tier2Count > 0
	result.tier3Matched = tier3Count > 0
	if result.tier1Matched {
		result.MatchedTiers = append(result.MatchedTiers, "tier-1")
	}
	if result.tier2Matched {
		result.MatchedTiers = append(result.MatchedTiers, "tier-2")
	}
	if result.tier3Matched {
		result.MatchedTiers = append(result.MatchedTiers, "tier-3")
	}

	return result
}

func applyToxicityPhraseHits(lower string, phrases []string, seen map[string]struct{}, tierCount *int, tierCap int, totalWeighted *int, tierWeight int) int {
	hits := 0
	for _, p := range phrases {
		if strings.Contains(lower, p) {
			hits++
			if *tierCount < tierCap {
				*tierCount++
				*totalWeighted += tierWeight
			}
			seen[p] = struct{}{}
		}
	}
	return hits
}

func applyToxicityTier3Hits(lower string, seen map[string]struct{}, tier3Count *int, totalWeighted *int) int {
	hits := 0
	for _, m := range toxicityTier3Pattern.FindAllString(lower, -1) {
		hits++
		if *tier3Count < toxicityTier3MaxCount {
			*tier3Count++
			*totalWeighted += toxicityTier3Weight
		}
		seen[m] = struct{}{}
	}
	return hits
}
