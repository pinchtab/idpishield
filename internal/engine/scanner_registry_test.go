package engine

import "testing"

type testInternalScanner struct {
	name   string
	result internalScanResult
	panic  bool
	calls  *[]string
}

func (s *testInternalScanner) Name() string { return s.name }

func (s *testInternalScanner) Scan(ctx internalScanContext) internalScanResult {
	if s.panic {
		panic("boom")
	}
	if s.calls != nil {
		*s.calls = append(*s.calls, s.name)
	}
	return s.result
}

func TestRunCustomScanners_SingleScanner(t *testing.T) {
	scanners := []internalScanner{
		{
			scanner: &testInternalScanner{
				name: "test",
				result: internalScanResult{
					Score:    20,
					Category: "test",
					Reason:   "matched",
					Matched:  true,
				},
			},
			name:     "test",
			scoreCap: 50,
		},
	}

	result := runCustomScanners(scanners, internalScanContext{})
	if result.TotalScore != 20 {
		t.Fatalf("expected score 20, got %d", result.TotalScore)
	}
	if len(result.Categories) != 1 || result.Categories[0] != "test" {
		t.Fatalf("expected category test, got %v", result.Categories)
	}
}

func TestRunCustomScanners_PanicRecovery(t *testing.T) {
	scanners := []internalScanner{
		{
			scanner:  &testInternalScanner{name: "panic", panic: true},
			name:     "panic",
			scoreCap: 50,
		},
	}

	result := runCustomScanners(scanners, internalScanContext{})
	if result.TotalScore != 0 {
		t.Fatalf("expected score 0, got %d", result.TotalScore)
	}
	if result.Matched {
		t.Fatalf("expected no matches for panicking scanner")
	}
}

func TestRunCustomScanners_ScoreCap(t *testing.T) {
	scanners := []internalScanner{
		{
			scanner: &testInternalScanner{
				name:   "cap-test",
				result: internalScanResult{Score: 100, Matched: true},
			},
			name:     "cap-test",
			scoreCap: 30,
		},
	}

	result := runCustomScanners(scanners, internalScanContext{})
	if result.TotalScore != 30 {
		t.Fatalf("expected capped score 30, got %d", result.TotalScore)
	}
}

func TestRunCustomScanners_MultipleScannersAggregate(t *testing.T) {
	scanners := []internalScanner{
		{
			scanner:  &testInternalScanner{name: "a", result: internalScanResult{Score: 10, Matched: true}},
			name:     "a",
			scoreCap: 50,
		},
		{
			scanner:  &testInternalScanner{name: "b", result: internalScanResult{Score: 15, Matched: true}},
			name:     "b",
			scoreCap: 50,
		},
		{
			scanner:  &testInternalScanner{name: "c", result: internalScanResult{Score: 20, Matched: true}},
			name:     "c",
			scoreCap: 50,
		},
	}

	result := runCustomScanners(scanners, internalScanContext{})
	if result.TotalScore != 45 {
		t.Fatalf("expected score 45, got %d", result.TotalScore)
	}
}

func TestRunCustomScanners_NilScannerSkipped(t *testing.T) {
	scanners := []internalScanner{{name: "nil", scoreCap: 50}}
	result := runCustomScanners(scanners, internalScanContext{})
	if result.TotalScore != 0 || result.Matched {
		t.Fatalf("expected empty result, got %+v", result)
	}
}

func TestRunCustomScanners_EmptyList(t *testing.T) {
	result := runCustomScanners([]internalScanner{}, internalScanContext{})
	if result.TotalScore != 0 {
		t.Fatalf("expected score 0, got %d", result.TotalScore)
	}
	if result.Matched {
		t.Fatalf("expected no matches")
	}
}

func TestRunCustomScanners_PriorityOrdering(t *testing.T) {
	order := make([]string, 0, 2)
	scanners := []internalScanner{
		{
			scanner:  &testInternalScanner{name: "low", calls: &order, result: internalScanResult{Matched: true}},
			name:     "low",
			priority: 1,
			scoreCap: 50,
		},
		{
			scanner:  &testInternalScanner{name: "high", calls: &order, result: internalScanResult{Matched: true}},
			name:     "high",
			priority: 10,
			scoreCap: 50,
		},
	}

	runCustomScanners(scanners, internalScanContext{})
	if len(order) != 2 {
		t.Fatalf("expected 2 scanner calls, got %d", len(order))
	}
	if order[0] != "high" || order[1] != "low" {
		t.Fatalf("expected priority order [high low], got %v", order)
	}
}

func TestRunLayeredScanners_EarlyExit(t *testing.T) {
	vectorScanner := internalScanner{
		scanner:  &testInternalScanner{name: "vector", result: internalScanResult{Matched: true, Score: 10}},
		name:     "vector",
		priority: 0,
		scoreCap: 50,
	}
	llmScanner := internalScanner{
		scanner:  &testInternalScanner{name: "llm", result: internalScanResult{Matched: true, Score: 5}},
		name:     "llm",
		priority: 0,
		scoreCap: 50,
	}
	scanners := []LayeredScanner{
		{Layer: ScannerLayerVector, Scanner: vectorScanner},
		{Layer: ScannerLayerLLM, Scanner: llmScanner},
	}

	total, layers := runLayeredScanners(scanners, internalScanContext{CurrentScore: pipelineEarlyExitScore}, false)
	if total.TotalScore != 10 {
		t.Fatalf("expected only first layer score 10 on early exit, got %d", total.TotalScore)
	}
	if len(layers) != 1 {
		t.Fatalf("expected one layer execution before early exit, got %v", layers)
	}
	if !layers[0].EarlyExit {
		t.Fatalf("expected early_exit marker on executed layer")
	}
}
