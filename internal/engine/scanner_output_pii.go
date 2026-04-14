package engine

import (
	"net"
	"regexp"
	"sort"
	"strings"
)

const (
	outputPIISSNContextWindow        = 48
	outputPIIPhoneContextWindow      = 64
	outputPIINamePatternMinCount     = 2
	outputPIISingleLineCommentPrefix = "//"
	outputPIIShellCommentPrefix      = "#"
	outputPIIConfidenceHigh          = "high"
	outputPIIConfidenceMedium        = "medium"
)

type piiMatch struct {
	Type  string
	Value string
	Start int
	End   int
}

type outputPIIResult struct {
	HasPII       bool
	PIITypes     []string
	MatchCount   int
	Redacted     string
	PIIDetails   []piiMatch
	HighCount    int
	MediumCount  int
	LowCount     int
	SecretHigh   bool
	SecretMedium bool
}

var outputPIIEmailPattern = regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`)
var outputPIISSNPattern = regexp.MustCompile(`\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`)
var outputPIICreditCardPattern = regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`)
var outputPIIPhonePattern = regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`)
var outputPIIPrivateIPPattern = regexp.MustCompile(`\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b`)
var outputPIIPublicIPPattern = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
var outputPIINamePattern = regexp.MustCompile(`\b[A-Z][a-z]+ [A-Z][a-z]+\b`)
var outputPIISecretAssignmentPattern = regexp.MustCompile(`(?i)\b(?:api[_\-]?key|token|secret|password)\b\s*[:=]\s*\S{8,}`)
var outputPIISecretPrefixPattern = regexp.MustCompile(`\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{59}|sk-ant-[A-Za-z0-9\-_]{90,}|sk-[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{37}|npm_[A-Za-z0-9]{36}|AIza[0-9A-Za-z\-_]{35}|sk_live_[A-Za-z0-9]{24,}|pk_live_[A-Za-z0-9]{24,}|xox[baprs]-[0-9A-Za-z\-]{10,48})\b`)
var outputPIIAzureSASPattern = regexp.MustCompile(`(?i)\bsig=[a-zA-Z0-9%]{40,}\b`)
var outputPIIAWSSecretPattern = regexp.MustCompile(`\b[0-9a-zA-Z/+]{40}\b`)

var outputPIISSNContextWords = []string{"ssn", "social security", "social sec"}
var outputPIIPhoneContextWords = []string{"phone", "call", "mobile", "cell", "tel", "contact"}
var outputPIIExampleEmails = map[string]struct{}{
	"example@example.com": {},
	"user@domain.com":     {},
	"test@test.com":       {},
	"foo@bar.com":         {},
}

// scanOutputPII detects PII in output text and returns a fully redacted copy for safe logging.
func scanOutputPII(text string) outputPIIResult {
	result := outputPIIResult{PIITypes: []string{}, PIIDetails: []piiMatch{}, Redacted: ""}
	if strings.TrimSpace(text) == "" {
		return result
	}

	lower := strings.ToLower(text)
	ranges := outputCodeFenceRanges(text)
	typeSeen := make(map[string]struct{})
	details := make([]piiMatch, 0)

	addMatch := func(m piiMatch, confidence string) {
		details = append(details, m)
		typeSeen[m.Type] = struct{}{}
		switch confidence {
		case outputPIIConfidenceHigh:
			result.HighCount++
		case outputPIIConfidenceMedium:
			result.MediumCount++
		default:
			result.LowCount++
		}
	}

	addOutputPIIEmailMatches(text, ranges, addMatch)
	addOutputPIISSNMatches(text, lower, ranges, addMatch)
	addOutputPIICreditCardMatches(text, ranges, addMatch)
	addOutputPIIPhoneMatches(text, lower, ranges, addMatch)
	addOutputPIIIPMatches(text, ranges, addMatch)
	addOutputPIINamePatternSignal(text, ranges, &result, typeSeen)
	addOutputPIISecretSignal(text, typeSeen, &result)

	if len(details) == 0 && len(typeSeen) == 0 {
		return result
	}

	result.HasPII = true
	result.PIIDetails = details
	result.MatchCount = len(details)
	result.PIITypes = mapKeysSorted(typeSeen)
	result.Redacted = buildOutputPIIRedactedText(text, details)
	return result
}

// addOutputPIIEmailMatches appends email matches that are not in ignored or example contexts.
func addOutputPIIEmailMatches(text string, ranges [][2]int, add func(m piiMatch, confidence string)) {
	for _, loc := range outputPIIEmailPattern.FindAllStringIndex(text, -1) {
		value := text[loc[0]:loc[1]]
		if _, isExample := outputPIIExampleEmails[strings.ToLower(value)]; isExample {
			continue
		}
		if isOutputPIIIgnoredContext(text, loc[0], ranges) {
			continue
		}
		add(piiMatch{Type: "email", Value: value, Start: loc[0], End: loc[1]}, outputPIIConfidenceHigh)
	}
}

// addOutputPIISSNMatches appends SSN matches when nearby SSN context is present.
func addOutputPIISSNMatches(text, lower string, ranges [][2]int, add func(m piiMatch, confidence string)) {
	for _, loc := range outputPIISSNPattern.FindAllStringIndex(text, -1) {
		if !outputHasNearbyContext(lower, loc[0], loc[1], outputPIISSNContextWords, outputPIISSNContextWindow) {
			continue
		}
		if isOutputPIIIgnoredContext(text, loc[0], ranges) {
			continue
		}
		add(piiMatch{Type: "ssn", Value: text[loc[0]:loc[1]], Start: loc[0], End: loc[1]}, outputPIIConfidenceHigh)
	}
}

// addOutputPIICreditCardMatches appends credit-card matches outside ignored contexts.
func addOutputPIICreditCardMatches(text string, ranges [][2]int, add func(m piiMatch, confidence string)) {
	for _, loc := range outputPIICreditCardPattern.FindAllStringIndex(text, -1) {
		if isOutputPIIIgnoredContext(text, loc[0], ranges) {
			continue
		}
		add(piiMatch{Type: "credit-card", Value: text[loc[0]:loc[1]], Start: loc[0], End: loc[1]}, outputPIIConfidenceHigh)
	}
}

// addOutputPIIPhoneMatches appends phone matches only when nearby phone context exists.
func addOutputPIIPhoneMatches(text, lower string, ranges [][2]int, add func(m piiMatch, confidence string)) {
	for _, loc := range outputPIIPhonePattern.FindAllStringIndex(text, -1) {
		if !outputHasNearbyContext(lower, loc[0], loc[1], outputPIIPhoneContextWords, outputPIIPhoneContextWindow) {
			continue
		}
		if isOutputPIIIgnoredContext(text, loc[0], ranges) {
			continue
		}
		add(piiMatch{Type: "phone", Value: text[loc[0]:loc[1]], Start: loc[0], End: loc[1]}, outputPIIConfidenceMedium)
	}
}

// addOutputPIIIPMatches appends private/public IP address matches outside ignored contexts.
func addOutputPIIIPMatches(text string, ranges [][2]int, add func(m piiMatch, confidence string)) {
	for _, loc := range outputPIIPrivateIPPattern.FindAllStringIndex(text, -1) {
		if isOutputPIIIgnoredContext(text, loc[0], ranges) {
			continue
		}
		add(piiMatch{Type: "ip-address", Value: text[loc[0]:loc[1]], Start: loc[0], End: loc[1]}, outputPIIConfidenceMedium)
	}
	for _, loc := range outputPIIPublicIPPattern.FindAllStringIndex(text, -1) {
		candidate := text[loc[0]:loc[1]]
		if outputPIIPrivateIPPattern.MatchString(candidate) {
			continue
		}
		if !isValidOutputPublicIPv4(candidate) {
			continue
		}
		if isOutputPIIIgnoredContext(text, loc[0], ranges) {
			continue
		}
		add(piiMatch{Type: "ip-address", Value: candidate, Start: loc[0], End: loc[1]}, outputPIIConfidenceMedium)
	}
}

func isValidOutputPublicIPv4(candidate string) bool {
	ip := net.ParseIP(strings.TrimSpace(candidate))
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}

	if v4[0] == 10 {
		return false
	}
	if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
		return false
	}
	if v4[0] == 192 && v4[1] == 168 {
		return false
	}

	return true
}

// addOutputPIINamePatternSignal adds a low-confidence name-pattern signal only with other PII present.
func addOutputPIINamePatternSignal(text string, ranges [][2]int, result *outputPIIResult, typeSeen map[string]struct{}) {
	nameMatches := 0
	for _, loc := range outputPIINamePattern.FindAllStringIndex(text, -1) {
		if isOutputPIIIgnoredContext(text, loc[0], ranges) {
			continue
		}
		nameMatches++
	}
	if nameMatches >= outputPIINamePatternMinCount && (result.HighCount > 0 || result.MediumCount > 0) {
		result.LowCount++
		typeSeen["name-pattern"] = struct{}{}
	}
}

// addOutputPIISecretSignal adds API key/secret signal counts from the existing secret scanner.
func addOutputPIISecretSignal(text string, typeSeen map[string]struct{}, result *outputPIIResult) {
	secrets := scanSecrets(text)
	if !secrets.HasSecrets {
		return
	}
	switch secrets.Confidence {
	case outputPIIConfidenceHigh:
		result.HighCount++
		result.SecretHigh = true
	case outputPIIConfidenceMedium:
		result.MediumCount++
		result.SecretMedium = true
	}
	typeSeen["api-key"] = struct{}{}
}

// outputCodeFenceRanges returns byte ranges for fenced code blocks to suppress code-snippet false positives.
func outputCodeFenceRanges(text string) [][2]int {
	ranges := make([][2]int, 0)
	start := 0
	for {
		i := strings.Index(text[start:], "```")
		if i < 0 {
			break
		}
		s := start + i
		j := strings.Index(text[s+3:], "```")
		if j < 0 {
			ranges = append(ranges, [2]int{s, len(text)})
			break
		}
		e := s + 3 + j + 3
		ranges = append(ranges, [2]int{s, e})
		start = e
		if start >= len(text) {
			break
		}
	}
	return ranges
}

// isOutputPIIIgnoredContext reports whether a match sits inside fenced code or comment-like lines.
func isOutputPIIIgnoredContext(text string, idx int, codeRanges [][2]int) bool {
	for _, r := range codeRanges {
		if idx >= r[0] && idx < r[1] {
			return true
		}
	}
	lineStart := strings.LastIndex(text[:idx], "\n") + 1
	lineEnd := strings.Index(text[idx:], "\n")
	if lineEnd < 0 {
		lineEnd = len(text)
	} else {
		lineEnd = idx + lineEnd
	}
	line := strings.TrimSpace(text[lineStart:lineEnd])
	return strings.HasPrefix(line, outputPIISingleLineCommentPrefix) || strings.HasPrefix(line, outputPIIShellCommentPrefix)
}

// outputHasNearbyContext checks whether any context term appears around a match window.
func outputHasNearbyContext(lower string, start, end int, terms []string, window int) bool {
	left := start - window
	if left < 0 {
		left = 0
	}
	right := end + window
	if right > len(lower) {
		right = len(lower)
	}
	ctx := lower[left:right]
	for _, t := range terms {
		if strings.Contains(ctx, t) {
			return true
		}
	}
	return false
}

// buildOutputPIIRedactedText constructs a safe redacted string that never leaks raw PII values.
func buildOutputPIIRedactedText(text string, details []piiMatch) string {
	redacted := redactPIIText(text, details)
	if redacted == "" {
		redacted = text
	}
	redacted = redactOutputSecrets(redacted)
	if strings.TrimSpace(redacted) == "" {
		return "[REDACTED]"
	}
	return redacted
}

// redactPIIText replaces matched PII ranges with stable redaction tags.
func redactPIIText(text string, details []piiMatch) string {
	if len(details) == 0 {
		return ""
	}
	out := text
	sorted := make([]piiMatch, len(details))
	copy(sorted, details)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Start > sorted[j].Start })
	for _, d := range sorted {
		tag := piiRedactionTag(d.Type)
		if d.Start < 0 || d.End > len(out) || d.Start >= d.End {
			continue
		}
		out = out[:d.Start] + tag + out[d.End:]
	}
	return out
}

// redactOutputSecrets redacts secret-like assignments and known key prefixes.
func redactOutputSecrets(text string) string {
	out := outputPIISecretAssignmentPattern.ReplaceAllString(text, "[REDACTED-API-KEY]")
	out = outputPIISecretPrefixPattern.ReplaceAllString(out, "[REDACTED-API-KEY]")
	out = outputPIIAzureSASPattern.ReplaceAllString(out, "sig=[REDACTED-SAS]")
	out = redactAWSSecretKeys(out)
	return out
}

// redactAWSSecretKeys redacts 40-char base64-like tokens that appear in AWS secret context.
func redactAWSSecretKeys(text string) string {
	contextPattern := regexp.MustCompile(`(?i)\b(?:aws|secret)\b`)
	for _, loc := range outputPIIAWSSecretPattern.FindAllStringIndex(text, -1) {
		start := loc[0] - 50
		if start < 0 {
			start = 0
		}
		end := loc[1] + 50
		if end > len(text) {
			end = len(text)
		}
		if contextPattern.FindStringIndex(text[start:end]) != nil {
			text = text[:loc[0]] + "[REDACTED-AWS-SECRET]" + text[loc[1]:]
		}
	}
	return text
}

// piiRedactionTag returns the canonical replacement tag for a detected PII type.
func piiRedactionTag(t string) string {
	switch t {
	case "email":
		return "[REDACTED-EMAIL]"
	case "ssn":
		return "[REDACTED-SSN]"
	case "credit-card":
		return "[REDACTED-CREDIT-CARD]"
	case "phone":
		return "[REDACTED-PHONE]"
	case "ip-address":
		return "[REDACTED-IP-ADDRESS]"
	default:
		return "[REDACTED-API-KEY]"
	}
}
