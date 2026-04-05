package engine

import (
	"sort"
	"strings"
)

const outputPatternLeak = "output.leak.system_prompt"
const outputPatternURL = "output.url.suspicious"
const outputPatternPII = "output.pii.detected"
const outputPatternCode = "output.code.harmful"
const outputPatternCodeAny = "output.code.present"
const outputPatternLowRelevance = "output.relevance.low"

const (
	outputScoreMax = 100

	outputLeakHighScoreWeight   = 30
	outputLeakMediumScoreWeight = 18
	outputLeakLowScoreWeight    = 8
	outputLeakScoreCap          = 60
	outputLeakLowOnlyScoreCap   = 10

	outputURLHighScoreWeight = 25
	outputURLMedScoreWeight  = 12
	outputURLLowScoreWeight  = 5
	outputURLScoreCap        = 50

	outputPIIHighScoreWeight = 25
	outputPIIMedScoreWeight  = 12
	outputPIILowScoreWeight  = 5
	outputPIIScoreCap        = 60

	outputCodeCriticalScoreWeight = 35
	outputCodeHighScoreWeight     = 20
	outputCodeMediumScoreWeight   = 10
	outputCodeScoreCap            = 65

	outputRelevanceBasePenalty = 15
	outputRelevanceDriftBonus  = 4
	outputRelevancePenaltyCap  = 25
	outputReasonPartsCapacity  = 6

	outputLeakPIIBonus        = 10
	outputURLPIIBonus         = 12
	outputURLCodeBonus        = 8
	outputCombinationBonusCap = 20
)

// assessOutput runs output-side scanners and assembles a RiskResult for LLM responses.
func assessOutput(text, originalPrompt string, cfg Config) RiskResult {
	trimmed := strings.TrimSpace(text)
	base := SafeResult()
	base.IsOutputScan = true
	base.RelevanceScore = outputRelevanceUnavailableScore
	if trimmed == "" {
		base.Reason = "No output text provided"
		return base
	}

	leak := scanOutputSystemPromptLeak(trimmed)
	urlResult := scanOutputMaliciousURLs(trimmed)
	pii := scanOutputPII(trimmed)
	code := scanOutputCode(trimmed, outputCodeConfig{AllowCode: cfg.AllowOutputCode, BanCode: cfg.BanOutputCode})
	relevance := scanOutputRelevance(trimmed, originalPrompt)

	score := 0
	score += outputLeakScore(leak)
	score += outputURLScore(urlResult)
	score += outputPIIScore(pii)
	score += outputCodeScore(code)
	score += outputRelevanceScore(relevance)
	score += outputCombinationBonus(leak, urlResult, pii, code)
	if score > outputScoreMax {
		score = outputScoreMax
	}

	patterns := outputPatterns(leak, urlResult, pii, code, relevance)
	categories := outputCategories(leak, urlResult, pii, code, relevance)
	reason := outputReason(leak, urlResult, pii, code, relevance)
	if reason == "" {
		reason = "No threats detected"
	}

	result := RiskResult{
		Score:               score,
		Level:               ScoreToLevel(score),
		Blocked:             ShouldBlock(score, cfg.StrictMode, cfg.BlockThreshold),
		Reason:              reason,
		Patterns:            patterns,
		Categories:          categories,
		BanListMatches:      []string{},
		OverDefenseRisk:     0,
		IsOutputScan:        true,
		PIIFound:            pii.HasPII,
		PIITypes:            pii.PIITypes,
		RedactedText:        pii.Redacted,
		RelevanceScore:      relevance.Relevance,
		CodeDetected:        code.HasCode,
		HarmfulCodePatterns: code.HarmfulPatterns,
		Intent:              deriveOutputIntent(leak, pii, urlResult, code, relevance),
	}

	if !result.PIIFound {
		result.RedactedText = ""
	}
	if !relevance.Computed {
		result.RelevanceScore = outputRelevanceUnavailableScore
	}
	return result
}

// outputLeakScore returns leak contribution with a low-confidence-only cap.
func outputLeakScore(r outputLeakResult) int {
	if r.HighMatches == 0 && r.MediumMatches == 0 && r.LowMatches > 0 {
		score := r.LowMatches * outputLeakLowScoreWeight
		if score > outputLeakLowOnlyScoreCap {
			return outputLeakLowOnlyScoreCap
		}
		return score
	}
	score := (r.HighMatches * outputLeakHighScoreWeight) + (r.MediumMatches * outputLeakMediumScoreWeight) + (r.LowMatches * outputLeakLowScoreWeight)
	if score > outputLeakScoreCap {
		return outputLeakScoreCap
	}
	return score
}

// outputURLScore returns URL contribution with a fixed cap.
func outputURLScore(r outputURLResult) int {
	score := (r.HighCount * outputURLHighScoreWeight) + (r.MediumCount * outputURLMedScoreWeight) + (r.LowCount * outputURLLowScoreWeight)
	if score > outputURLScoreCap {
		return outputURLScoreCap
	}
	return score
}

// outputPIIScore returns PII contribution with a fixed cap.
func outputPIIScore(r outputPIIResult) int {
	score := (r.HighCount * outputPIIHighScoreWeight) + (r.MediumCount * outputPIIMedScoreWeight) + (r.LowCount * outputPIILowScoreWeight)
	if score > outputPIIScoreCap {
		return outputPIIScoreCap
	}
	return score
}

// outputCodeScore returns code contribution with a fixed cap.
func outputCodeScore(r outputCodeResult) int {
	score := (r.CriticalCount * outputCodeCriticalScoreWeight) + (r.HighCount * outputCodeHighScoreWeight) + (r.MediumCount * outputCodeMediumScoreWeight)
	if score > outputCodeScoreCap {
		return outputCodeScoreCap
	}
	return score
}

// outputRelevanceScore returns relevance-drift contribution with a fixed cap.
func outputRelevanceScore(r outputRelevanceResult) int {
	if !r.Computed || !r.IsLowRelevance {
		return 0
	}
	score := outputRelevanceBasePenalty + (len(r.DriftPhrases) * outputRelevanceDriftBonus)
	if score > outputRelevancePenaltyCap {
		return outputRelevancePenaltyCap
	}
	return score
}

// outputCombinationBonus adds bounded bonuses for multi-signal output attacks.
func outputCombinationBonus(leak outputLeakResult, urls outputURLResult, pii outputPIIResult, code outputCodeResult) int {
	bonus := 0
	if leak.HasLeak && pii.HasPII {
		bonus += outputLeakPIIBonus
	}
	if urls.HasMaliciousURL && pii.HasPII {
		bonus += outputURLPIIBonus
	}
	if urls.HasMaliciousURL && code.HasHarmfulCode {
		bonus += outputURLCodeBonus
	}
	if bonus > outputCombinationBonusCap {
		return outputCombinationBonusCap
	}
	return bonus
}

// outputPatterns builds the output pattern ID list.
func outputPatterns(leak outputLeakResult, urls outputURLResult, pii outputPIIResult, code outputCodeResult, relevance outputRelevanceResult) []string {
	set := make(map[string]struct{})
	if leak.HasLeak {
		set[outputPatternLeak] = struct{}{}
	}
	if urls.HasMaliciousURL {
		set[outputPatternURL] = struct{}{}
	}
	if pii.HasPII {
		set[outputPatternPII] = struct{}{}
	}
	if code.HasCode {
		set[outputPatternCodeAny] = struct{}{}
	}
	if code.HasHarmfulCode {
		set[outputPatternCode] = struct{}{}
	}
	if relevance.IsLowRelevance {
		set[outputPatternLowRelevance] = struct{}{}
	}
	return mapKeysSorted(set)
}

// outputCategories builds the output category list.
func outputCategories(leak outputLeakResult, urls outputURLResult, pii outputPIIResult, code outputCodeResult, relevance outputRelevanceResult) []string {
	set := make(map[string]struct{})
	if leak.HasLeak {
		set["system-prompt-leak"] = struct{}{}
	}
	if urls.HasMaliciousURL {
		set["malicious-url"] = struct{}{}
	}
	if pii.HasPII {
		set["pii"] = struct{}{}
	}
	if code.HasCode {
		set["code"] = struct{}{}
	}
	if code.HasHarmfulCode {
		set["harmful-code"] = struct{}{}
	}
	if relevance.IsLowRelevance {
		set["low-relevance"] = struct{}{}
	}
	return mapKeysSorted(set)
}

// outputReason builds a deterministic textual explanation from fired output signals.
func outputReason(leak outputLeakResult, urls outputURLResult, pii outputPIIResult, code outputCodeResult, relevance outputRelevanceResult) string {
	parts := make([]string, 0, outputReasonPartsCapacity)
	if leak.HasLeak {
		parts = append(parts, "system prompt leakage indicators detected")
	}
	if urls.HasMaliciousURL {
		parts = append(parts, "suspicious URL indicators detected")
	}
	if pii.HasPII {
		parts = append(parts, "PII exposure detected")
	}
	if code.HasHarmfulCode {
		parts = append(parts, "harmful code patterns detected")
	} else if code.HasCode {
		parts = append(parts, "code present in output")
	}
	if relevance.IsLowRelevance {
		parts = append(parts, "response relevance drift detected")
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// deriveOutputIntent maps output-side signal combinations to the dominant attacker intent.
func deriveOutputIntent(leak outputLeakResult, pii outputPIIResult, urls outputURLResult, code outputCodeResult, relevance outputRelevanceResult) Intent {
	if leak.HasLeak || pii.HasPII {
		return IntentDataExfiltration
	}
	if urls.HasMaliciousURL {
		return IntentSystemCompromise
	}
	if code.HasHarmfulCode {
		return IntentSystemCompromise
	}
	if relevance.IsLowRelevance {
		return IntentOutputSteering
	}
	return IntentNone
}
