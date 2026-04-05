package engine

import (
	"strings"
	"testing"
)

func TestScanOutputPII_DetectsAndRedacts(t *testing.T) {
	text := "Contact Jane at jane.doe@corp.com or call phone 415-555-1212."
	result := scanOutputPII(text)
	if !result.HasPII {
		t.Fatalf("expected pii detection, got %+v", result)
	}
	if len(result.PIITypes) == 0 {
		t.Fatalf("expected pii types")
	}
	if result.Redacted == "" {
		t.Fatalf("expected redacted text")
	}
}

func TestScanOutputPII_IgnoresExampleEmail(t *testing.T) {
	text := "Use example@example.com in docs."
	result := scanOutputPII(text)
	if result.HasPII {
		t.Fatalf("expected no pii for example email, got %+v", result)
	}
}

func TestOutputPII_TwoCapitalWordsNotPII(t *testing.T) {
	text := "The United States has many national parks worth visiting."
	result := scanOutputPII(text)
	if result.HasPII {
		t.Fatalf("expected capitalized words alone not to trigger PII, got %+v", result)
	}
}

func TestOutputPII_RedactedTextIsComplete(t *testing.T) {
	text := "Email us at secret@internal-company.com for support."
	result := scanOutputPII(text)
	if !result.HasPII {
		t.Fatalf("expected pii detection, got %+v", result)
	}
	if strings.Contains(result.Redacted, "@") {
		t.Fatalf("expected redacted text to remove raw email, got %q", result.Redacted)
	}
	if !strings.Contains(result.Redacted, "[REDACTED-EMAIL]") {
		t.Fatalf("expected redacted email tag, got %q", result.Redacted)
	}
	if !strings.Contains(result.Redacted, "Email us at") {
		t.Fatalf("expected prefix text to be preserved, got %q", result.Redacted)
	}
	if !strings.Contains(result.Redacted, "for support.") {
		t.Fatalf("expected suffix text to be preserved, got %q", result.Redacted)
	}
}
