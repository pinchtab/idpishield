package engine

import (
	"regexp"
	"sort"
	"strings"
)

type banListConfig struct {
	BanSubstrings       []string
	BanTopics           []string
	BanCompetitors      []string
	CompiledTopics      []*regexp.Regexp
	CompiledCompetitors []*regexp.Regexp
	CompiledRegex       []*regexp.Regexp
}

type banListResult struct {
	HasBanMatch       bool
	MatchedRules      []string
	MatchedCategory   string
	HighestPriority   string
	SubstringMatches  int
	TopicMatches      int
	CompetitorMatches int
	RegexMatches      int
}

// Scoring is intentionally conservative: no single ban-list signal
// alone crosses the block threshold (60 in balanced mode).
// Blocking requires either a CustomRegex match combined with other
// signals, or multiple ban-list rules firing simultaneously.
// This prevents accidental over-blocking on benign content.
const (
	banListSubstringScore  = 30
	banListTopicScore      = 20
	banListCompetitorScore = 15
	banListRegexScore      = 40
	banListContributionCap = 60
	banPatternIDSubstring  = "bl-sub-001"
	banPatternIDTopic      = "bl-top-001"
	banPatternIDCompetitor = "bl-cmp-001"
	banPatternIDRegex      = "bl-rgx-001"
)

const (
	banCategorySubstring  = "ban-substring"
	banCategoryTopic      = "ban-topic"
	banCategoryCompetitor = "ban-competitor"
	banCategoryRegex      = "custom-regex"
)

func scanBanLists(text string, cfg banListConfig) banListResult {
	result := banListResult{MatchedRules: []string{}}
	lowered := strings.ToLower(text)
	seenRules := make(map[string]struct{})
	// Rules are deduplicated after source merge (config struct, file, env)
	// so each logical rule contributes at most once during a single scan.

	// BanSubstrings uses simple contains() for maximum flexibility -
	// users who add "crypto" will also match "cryptocurrency".
	for _, phrase := range cfg.BanSubstrings {
		trimmed := strings.TrimSpace(phrase)
		if trimmed == "" {
			continue
		}
		if strings.Contains(lowered, strings.ToLower(trimmed)) {
			addBanRule("substring:"+trimmed, seenRules, &result)
			result.SubstringMatches++
		}
	}

	// BanTopics uses whole-word matching to avoid false positives,
	// e.g. ban topic "anal" should not match "analysis".
	result.TopicMatches += scanCompiledWordList(cfg.CompiledTopics, cfg.BanTopics, "topic:", seenRules, &result, lowered, text)
	// BanCompetitors also uses whole-word matching to avoid partial-word hits.
	result.CompetitorMatches += scanCompiledWordList(cfg.CompiledCompetitors, cfg.BanCompetitors, "competitor:", seenRules, &result, lowered, text)

	for _, re := range cfg.CompiledRegex {
		if re == nil {
			continue
		}
		if re.MatchString(text) {
			addBanRule("custom-regex:"+re.String(), seenRules, &result)
			result.RegexMatches++
		}
	}

	result.HasBanMatch = len(result.MatchedRules) > 0
	if !result.HasBanMatch {
		return result
	}

	// Ban list rules are explicit user intent. Unlike heuristic scanners,
	// ban rules should always fire when matched. Debias is skipped when
	// any ban-list category is present in results.
	result.MatchedRules = deduplicateStrings(result.MatchedRules)
	result.HighestPriority, result.MatchedCategory = resolveBanPriority(result)
	sort.Strings(result.MatchedRules)
	return result
}

func scanCompiledWordList(compiled []*regexp.Regexp, original []string, prefix string, seen map[string]struct{}, result *banListResult, lowered string, text string) int {
	_ = text
	matches := 0
	for i, re := range compiled {
		if re == nil || i >= len(original) {
			continue
		}
		trimmed := strings.TrimSpace(original[i])
		if trimmed == "" {
			continue
		}
		if re.MatchString(lowered) {
			addBanRule(prefix+trimmed, seen, result)
			matches++
		}
	}
	return matches
}

func addBanRule(rule string, seen map[string]struct{}, result *banListResult) {
	key := strings.ToLower(strings.TrimSpace(rule))
	if key == "" {
		return
	}
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	result.MatchedRules = append(result.MatchedRules, strings.TrimSpace(rule))
}

func resolveBanPriority(result banListResult) (string, string) {
	switch {
	case result.RegexMatches > 0:
		return banCategoryRegex, banCategoryRegex
	case result.SubstringMatches > 0:
		return banCategorySubstring, banCategorySubstring
	case result.CompetitorMatches > 0:
		return banCategoryCompetitor, banCategoryCompetitor
	case result.TopicMatches > 0:
		return banCategoryTopic, banCategoryTopic
	default:
		return "", ""
	}
}
