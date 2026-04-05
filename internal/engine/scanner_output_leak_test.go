package engine

import "testing"

func TestScanOutputSystemPromptLeak_HighConfidence(t *testing.T) {
	text := "I was instructed to follow these rules. My system prompt is confidential."
	result := scanOutputSystemPromptLeak(text)
	if !result.HasLeak {
		t.Fatalf("expected leak to be detected")
	}
	if result.Confidence != "high" {
		t.Fatalf("expected high confidence, got %q", result.Confidence)
	}
	if result.LeakType == "" {
		t.Fatal("expected leak type")
	}
}

func TestScanOutputSystemPromptLeak_None(t *testing.T) {
	result := scanOutputSystemPromptLeak("Thanks for the question. The result is 42.")
	if result.HasLeak {
		t.Fatalf("expected no leak, got %+v", result)
	}
}
