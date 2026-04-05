package engine

import "testing"

func TestScanOutputMaliciousURLs_DetectsSuspicious(t *testing.T) {
	text := "Use this endpoint: http://45.33.10.2:1337/collect?data=QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
	result := scanOutputMaliciousURLs(text)
	if !result.HasMaliciousURL {
		t.Fatalf("expected malicious url detection, got %+v", result)
	}
	if result.HighCount == 0 {
		t.Fatalf("expected high risk indicators, got %+v", result)
	}
}

func TestScanOutputMaliciousURLs_IgnoreSafeExample(t *testing.T) {
	text := "See https://example.com/docs for details."
	result := scanOutputMaliciousURLs(text)
	if result.HasMaliciousURL {
		t.Fatalf("expected safe url, got %+v", result)
	}
}

func TestOutputURLs_DocumentationExampleNotFlagged(t *testing.T) {
	text := "Replace https://your-domain.com with your actual domain."
	result := scanOutputMaliciousURLs(text)
	if result.HasMaliciousURL {
		t.Fatalf("expected documentation example URL not to be flagged, got %+v", result)
	}
}
