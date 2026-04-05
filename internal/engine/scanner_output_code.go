package engine

import (
	"regexp"
	"strings"
)

const (
	outputCodeDocumentationReduceDivisor = 2
)

type outputCodeConfig struct {
	AllowCode bool
	BanCode   bool
}

type outputCodeResult struct {
	HasCode         bool
	HasHarmfulCode  bool
	CodeLanguages   []string
	HarmfulPatterns []string
	CodeBlocks      []string
	CriticalCount   int
	HighCount       int
	MediumCount     int
}

var outputFencedCodePattern = regexp.MustCompile("(?s)```([a-zA-Z0-9#+-]*)\\n(.*?)```")
var outputShellLinePattern = regexp.MustCompile(`(?m)^\s*[$#]\s+\S+`)

var outputInlinePythonPattern = regexp.MustCompile(`\b(import\s+\w+|def\s+\w+\(|class\s+\w+|print\()`)
var outputInlineJSHashPattern = regexp.MustCompile(`\b(function\s+\w*\(|const\s+\w+|let\s+\w+|require\()`)
var outputInlineGoPattern = regexp.MustCompile(`\b(package\s+\w+|func\s+\w+\(|import\s*\()`)
var outputInlineBashPattern = regexp.MustCompile(`(?i)(#!/bin/bash|\bcurl\b|\bwget\b|\bchmod\b)`)

var outputCodeCriticalPatterns = map[string]*regexp.Regexp{
	"file-deletion":      regexp.MustCompile(`(?i)(rm\s+-rf|rmdir\s+/s|os\.remove|shutil\.rmtree|Delete-Item\s+-Recurse)`),
	"fork-bomb":          regexp.MustCompile(`(?i)(:\(\)\{.*\}|fork\(\)|while\s*true|while\s*1:\s*pass)`),
	"system-file-modify": regexp.MustCompile(`(?i)(/etc/passwd|/etc/shadow|C:\\Windows\\System32|HKEY_LOCAL_MACHINE|registry)`),
	"reverse-shell":      regexp.MustCompile(`(?i)(bash\s+-i\s+>&|nc\s+-e|/dev/tcp/|python.*socket.*connect|powershell.*webclient)`),
}

var outputCodeHighPatterns = map[string]*regexp.Regexp{
	"network-ip-request": regexp.MustCompile(`(?i)(curl|wget|fetch|requests\.(get|post)).*(https?://\d{1,3}(?:\.\d{1,3}){3}|\.xyz|\.tk|\.ml|\.ga)`),
	"env-leak-network":   regexp.MustCompile(`(?i)(os\.environ|process\.env|\$env:|%[A-Z_]+%).*(curl|wget|requests\.|fetch|http)`),
	"base64-network":     regexp.MustCompile(`(?i)(base64|b64encode|encode).*(curl|wget|requests\.|fetch|http)`),
	"spawn-subprocess":   regexp.MustCompile(`(?i)(subprocess\.|os\.system\(|exec\.Command\(|child_process)`),
	"obfuscated-code":    regexp.MustCompile(`(?i)(?:\b[a-zA-Z]\b\s*=){5,}|(?:0x[0-9a-f]{2}\s*){8,}`),
}

var outputCodeMediumPatterns = map[string]*regexp.Regexp{
	"filesystem-traversal": regexp.MustCompile(`(?i)(\.\./|\.\.\\|/home/|/root/|C:\\Users\\)`),
	"security-bypass":      regexp.MustCompile(`(?i)(verify\s*=\s*false|ssl_verify\s*=\s*false|InsecureSkipVerify|--no-check-certificate|rejectUnauthorized\s*:\s*false)`),
	"silent-install":       regexp.MustCompile(`(?i)(pip\s+install|npm\s+install|go\s+get|apt-get\s+install)`),
}

// scanOutputCode detects code in output text and classifies harmful code patterns.
func scanOutputCode(text string, cfg outputCodeConfig) outputCodeResult {
	result := outputCodeResult{CodeLanguages: []string{}, HarmfulPatterns: []string{}, CodeBlocks: []string{}}
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return result
	}

	langs := make(map[string]struct{})
	patternSeen := make(map[string]struct{})
	blocks := extractOutputCodeBlocks(trimmed, langs)
	result.CodeBlocks = blocks
	if len(blocks) > 0 || outputLooksLikeInlineCode(trimmed) {
		result.HasCode = true
	}
	if !result.HasCode {
		return result
	}

	content := blocks
	if len(content) == 0 {
		content = []string{trimmed}
	}

	for _, block := range content {
		c, h, m, fired := scanOutputCodeBlock(block)
		result.CriticalCount += c
		result.HighCount += h
		result.MediumCount += m
		for _, f := range fired {
			patternSeen[f] = struct{}{}
		}
	}

	if cfg.BanCode {
		result.MediumCount++
		patternSeen["code-present"] = struct{}{}
	}

	docStyle := isOutputCodeDocumentationContext(strings.ToLower(trimmed))
	if docStyle {
		result.CriticalCount = reduceHalf(result.CriticalCount)
		result.HighCount = reduceHalf(result.HighCount)
		result.MediumCount = reduceHalf(result.MediumCount)
	}
	if cfg.AllowCode {
		result.MediumCount = 0
	}

	if result.CriticalCount > 0 || result.HighCount > 0 || result.MediumCount > 0 {
		result.HasHarmfulCode = true
	}
	result.CodeLanguages = mapKeysSorted(langs)
	result.HarmfulPatterns = mapKeysSorted(patternSeen)
	return result
}

// extractOutputCodeBlocks extracts fenced code blocks and records language hints.
func extractOutputCodeBlocks(text string, langs map[string]struct{}) []string {
	matches := outputFencedCodePattern.FindAllStringSubmatch(text, -1)
	blocks := make([]string, 0, len(matches))
	for _, m := range matches {
		lang := strings.ToLower(strings.TrimSpace(m[1]))
		if lang != "" {
			langs[lang] = struct{}{}
		}
		blocks = append(blocks, m[2])
	}
	return blocks
}

// outputLooksLikeInlineCode reports whether non-fenced output still appears to contain code.
func outputLooksLikeInlineCode(text string) bool {
	if outputShellLinePattern.FindStringIndex(text) != nil {
		return true
	}
	return outputInlinePythonPattern.FindStringIndex(text) != nil ||
		outputInlineJSHashPattern.FindStringIndex(text) != nil ||
		outputInlineGoPattern.FindStringIndex(text) != nil ||
		outputInlineBashPattern.FindStringIndex(text) != nil
}

// scanOutputCodeBlock checks a single code block against critical/high/medium pattern sets.
func scanOutputCodeBlock(block string) (critical, high, medium int, fired []string) {
	for name, rx := range outputCodeCriticalPatterns {
		if rx.FindStringIndex(block) != nil {
			critical++
			fired = append(fired, name)
		}
	}
	for name, rx := range outputCodeHighPatterns {
		if rx.FindStringIndex(block) != nil {
			high++
			fired = append(fired, name)
		}
	}
	for name, rx := range outputCodeMediumPatterns {
		if rx.FindStringIndex(block) != nil {
			medium++
			fired = append(fired, name)
		}
	}
	return critical, high, medium, fired
}

// isOutputCodeDocumentationContext detects explanatory prose context around code snippets.
func isOutputCodeDocumentationContext(lower string) bool {
	return strings.Contains(lower, "for example") ||
		strings.Contains(lower, "this is how") ||
		strings.Contains(lower, "avoid")
}

// reduceHalf returns the rounded-up half of a positive integer.
func reduceHalf(v int) int {
	if v <= 0 {
		return 0
	}
	return (v + 1) / outputCodeDocumentationReduceDivisor
}
