package engine

import "testing"

func TestScanOutputRelevance_ComputesOverlap(t *testing.T) {
	prompt := "Explain secure API key storage best practices"
	output := "Best practices for API key storage include secret managers and rotation."
	result := scanOutputRelevance(output, prompt)
	if !result.Computed {
		t.Fatalf("expected computed relevance")
	}
	if result.Relevance <= 0 {
		t.Fatalf("expected positive relevance, got %f", result.Relevance)
	}
}

func TestScanOutputRelevance_LowRelevanceWithDrift(t *testing.T) {
	prompt := "Explain database indexing"
	output := "Buy now and click here for a limited offer"
	result := scanOutputRelevance(output, prompt)
	if !result.IsLowRelevance {
		t.Fatalf("expected low relevance, got %+v", result)
	}
}

func TestOutputRelevance_ShortPromptNoFalsePositive(t *testing.T) {
	prompt := "hi there"
	response := "I am talking about completely different topics now."
	result := scanOutputRelevance(response, prompt)
	if result.IsIrrelevant {
		t.Fatalf("expected short prompt to skip irrelevant flag, got %+v", result)
	}
}
