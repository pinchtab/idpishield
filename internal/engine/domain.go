package engine

import (
	"net/url"
	"strings"
)

// domainChecker validates URLs against a configured domain allowlist.
// If the allowlist is empty, all domains are permitted.
type domainChecker struct {
	patterns []string
}

func newDomainChecker(allowed []string) *domainChecker {
	normalized := make([]string, 0, len(allowed))
	for _, d := range allowed {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			normalized = append(normalized, d)
		}
	}
	return &domainChecker{patterns: normalized}
}

// IsAllowed checks whether a URL's domain matches the allowlist.
// Returns true if the allowlist is empty (no restrictions) or the domain matches.
func (d *domainChecker) IsAllowed(rawURL string) bool {
	if len(d.patterns) == 0 {
		return true
	}
	host := extractHost(rawURL)
	if host == "" {
		return false
	}
	for _, pattern := range d.patterns {
		if matchDomain(host, pattern) {
			return true
		}
	}
	return false
}

// CheckDomain builds a RiskResult for a domain check.
func (d *domainChecker) CheckDomain(rawURL string, strict bool) RiskResult {
	if len(d.patterns) == 0 {
		return SafeResult()
	}

	host := extractHost(rawURL)
	if host == "" {
		return RiskResult{
			Score:      30,
			Level:      ScoreToLevel(30),
			Blocked:    ShouldBlock(30, strict),
			Reason:     "Unable to parse domain from URL",
			Patterns:   []string{},
			Categories: []string{},
		}
	}

	if d.IsAllowed(rawURL) {
		return SafeResult()
	}

	score := 70
	return RiskResult{
		Score:      score,
		Level:      ScoreToLevel(score),
		Blocked:    ShouldBlock(score, strict),
		Reason:     "Domain not in allowlist: " + host,
		Patterns:   []string{},
		Categories: []string{},
	}
}

// extractHost parses a URL and returns the lowercase hostname without port.
func extractHost(rawURL string) string {
	raw := strings.TrimSpace(rawURL)
	if raw == "" {
		return ""
	}

	// If no scheme, prepend https:// so url.Parse works correctly.
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	host := u.Hostname()
	return strings.ToLower(host)
}

// matchDomain checks if host matches a domain pattern.
// Supports exact match and wildcard prefix (e.g., "*.example.com").
func matchDomain(host, pattern string) bool {
	// Catch-all wildcard
	if pattern == "*" {
		return true
	}

	// Wildcard pattern: *.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"

		// Must have the suffix and must not be the bare domain.
		// "sub.example.com" matches, "example.com" does not.
		return strings.HasSuffix(host, suffix) && host != suffix[1:]
	}

	// Exact match
	return host == pattern
}
