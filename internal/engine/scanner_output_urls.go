package engine

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const (
	outputURLQueryEntropyMinLength = 20
	outputURLQueryEntropyThreshold = 4.5
	outputURLLongURLThreshold      = 200
)

type outputURLResult struct {
	HasMaliciousURL bool
	URLs            []string
	SuspiciousURLs  []string
	RiskTypes       []string
	HighCount       int
	MediumCount     int
	LowCount        int
}

var outputURLPattern = regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`)
var outputSuspiciousBareDomainPattern = regexp.MustCompile(`\b(?:[a-zA-Z0-9-]+\.)+(?:xyz|tk|ml|ga|cf|gq|pw|top|click|download|zip)\b`)
var outputIPURLPattern = regexp.MustCompile(`(?i)^https?://\d{1,3}(?:\.\d{1,3}){3}`)
var outputDataSchemePattern = regexp.MustCompile(`(?i)data:[^;]+;base64`)
var outputNonStandardPortPattern = regexp.MustCompile(`(?i)^https?://[^/]+:(\d{2,5})(?:/|\?|#|$)`)
var outputEncodedPathPattern = regexp.MustCompile(`(?:%[0-9a-fA-F]{2}){4,}`)

var outputSuspiciousPathKeywords = []string{
	"exfil", "steal", "dump", "leak", "harvest", "collect",
	"callback", "webhook", "beacon", "ping", "track", "spy",
}

var outputTunnelDomains = []string{
	"ngrok.io", "ngrok.app", "tunnel.dev", "localtunnel.me",
	"serveo.net", "pagekite.me", "telebit.io", "localhost.run",
	"hookdeck.com", "smee.io",
}

var outputSafeDomains = []string{
	"google.com", "github.com", "stackoverflow.com", "wikipedia.org",
	"docs.microsoft.com", "developer.mozilla.org", "npmjs.com", "pypi.org",
	"crates.io", "golang.org", "pkg.go.dev",
}

var outputSuspiciousTLDs = []string{
	".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".click",
	".download", ".zip", ".mov", ".info",
}

var outputSafePorts = map[string]struct{}{
	"80": {}, "443": {}, "8080": {}, "8443": {}, "3000": {},
}

var outputDataQueryParamHints = []string{"data=", "payload=", "content=", "body=", "text=", "msg=", "q="}

// scanOutputMaliciousURLs extracts URLs and scores suspicious URL risk indicators.
func scanOutputMaliciousURLs(text string) outputURLResult {
	result := outputURLResult{URLs: []string{}, SuspiciousURLs: []string{}, RiskTypes: []string{}}

	urls := outputURLPattern.FindAllString(text, -1)
	urls = append(urls, outputSuspiciousBareDomainPattern.FindAllString(text, -1)...)
	if len(urls) == 0 {
		return result
	}

	urlSeen := make(map[string]struct{}, len(urls))
	riskSeen := make(map[string]struct{})
	suspSeen := make(map[string]struct{})

	for _, rawURL := range urls {
		norm := strings.TrimSpace(rawURL)
		if norm == "" {
			continue
		}
		if _, ok := urlSeen[norm]; ok {
			continue
		}
		urlSeen[norm] = struct{}{}
		result.URLs = append(result.URLs, norm)

		if isOutputURLSafeExample(text, norm) {
			continue
		}

		high, medium, low, riskTypes := scoreSingleOutputURL(norm)
		result.HighCount += high
		result.MediumCount += medium
		result.LowCount += low
		for _, rt := range riskTypes {
			riskSeen[rt] = struct{}{}
		}
		if high > 0 || medium > 0 || low > 0 {
			suspSeen[norm] = struct{}{}
		}
	}

	if len(suspSeen) > 0 {
		result.HasMaliciousURL = true
	}
	for s := range suspSeen {
		result.SuspiciousURLs = append(result.SuspiciousURLs, s)
	}
	for rt := range riskSeen {
		result.RiskTypes = append(result.RiskTypes, rt)
	}
	sort.Strings(result.URLs)
	sort.Strings(result.SuspiciousURLs)
	sort.Strings(result.RiskTypes)
	return result
}

// scoreSingleOutputURL scores one URL and returns count by severity plus risk type labels.
func scoreSingleOutputURL(rawURL string) (high, medium, low int, riskTypes []string) {
	urlLower := strings.ToLower(rawURL)
	risk := make(map[string]struct{})

	if outputIPURLPattern.MatchString(urlLower) {
		high++
		risk["ip-url"] = struct{}{}
	}
	if outputDataSchemePattern.MatchString(urlLower) {
		high++
		risk["data-exfiltration"] = struct{}{}
	}
	if hasOutputHighEntropyQueryValue(urlLower) {
		high++
		risk["high-entropy-query"] = struct{}{}
	}
	if containsAny(urlLower, outputTunnelDomains) {
		high++
		risk["tunnel-service"] = struct{}{}
	}
	if m := outputNonStandardPortPattern.FindStringSubmatch(urlLower); len(m) == 2 {
		if _, ok := outputSafePorts[m[1]]; !ok {
			high++
			risk["non-standard-port"] = struct{}{}
		}
	}

	if hasOutputSuspiciousTLD(urlLower) {
		medium++
		risk["suspicious-tld"] = struct{}{}
	}
	if outputEncodedPathPattern.FindStringIndex(urlLower) != nil {
		medium++
		risk["encoded-obfuscation"] = struct{}{}
	}
	if containsAny(urlLower, outputSuspiciousPathKeywords) {
		medium++
		risk["suspicious-path"] = struct{}{}
	}
	if len(rawURL) > outputURLLongURLThreshold {
		medium++
		risk["long-url"] = struct{}{}
	}

	if containsAny(urlLower, outputDataQueryParamHints) {
		low++
		risk["data-query"] = struct{}{}
	}

	for k := range risk {
		riskTypes = append(riskTypes, k)
	}
	sort.Strings(riskTypes)
	return high, medium, low, riskTypes
}

// hasOutputHighEntropyQueryValue checks query values for secret-like high-entropy tokens.
func hasOutputHighEntropyQueryValue(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	q := u.Query()
	for _, values := range q {
		for _, v := range values {
			if len(v) >= outputURLQueryEntropyMinLength && shannonEntropy(v) > outputURLQueryEntropyThreshold {
				return true
			}
		}
	}
	return false
}

// hasOutputSuspiciousTLD reports whether the URL contains a suspicious TLD.
func hasOutputSuspiciousTLD(urlLower string) bool {
	for _, tld := range outputSuspiciousTLDs {
		if strings.Contains(urlLower, tld) {
			return true
		}
	}
	return false
}

// isOutputURLSafeExample reports whether a URL appears to be documentation-only sample content.
func isOutputURLSafeExample(_ string, rawURL string) bool {
	host := extractOutputURLHost(rawURL)
	if host == "" {
		return false
	}
	if outputURLHostMatchesDomain(host, "example.com") ||
		outputURLHostMatchesDomain(host, "your-domain.com") ||
		outputURLHostMatchesDomain(host, "placeholder.com") {
		return true
	}

	for _, domain := range outputSafeDomains {
		if outputURLHostMatchesDomain(host, domain) {
			return true
		}
	}
	return false
}

// extractOutputURLHost parses a URL or bare domain and returns the normalized hostname.
func extractOutputURLHost(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	return host
}

// outputURLHostMatchesDomain checks exact host or subdomain match for an allowlisted domain.
func outputURLHostMatchesDomain(host, domain string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	d := strings.TrimSpace(strings.ToLower(domain))
	if h == "" || d == "" {
		return false
	}
	return h == d || strings.HasSuffix(h, "."+d)
}
