package benchmark

import (
	"os"
	"path/filepath"
	"testing"

	idpishield "github.com/pinchtab/idpi-shield"
)

func TestRunBenchmark(t *testing.T) {
	// Find the dataset directory relative to this test file.
	datasetDir := "dataset"
	if _, err := os.Stat(filepath.Join(datasetDir, "malicious")); err != nil {
		t.Skipf("dataset not found at %s, skipping benchmark test", datasetDir)
	}

	cfg := idpishield.Config{
		Mode:       idpishield.ModeBalanced,
		StrictMode: true,
	}

	report, err := RunBenchmark(datasetDir, cfg)
	if err != nil {
		t.Fatalf("RunBenchmark failed: %v", err)
	}

	if report.Metrics.TotalSamples == 0 {
		t.Fatal("expected samples, got 0")
	}

	t.Logf("Benchmark complete: %d samples", report.Metrics.TotalSamples)
	t.Logf("Accuracy:  %.1f%%", report.Metrics.Accuracy*100)
	t.Logf("Precision: %.1f%%", report.Metrics.Precision*100)
	t.Logf("Recall:    %.1f%%", report.Metrics.Recall*100)
	t.Logf("F1 Score:  %.1f%%", report.Metrics.F1Score*100)
	t.Logf("TP=%d TN=%d FP=%d FN=%d",
		report.Metrics.TruePositives, report.Metrics.TrueNegatives,
		report.Metrics.FalsePositives, report.Metrics.FalseNegatives)

	// Print text report
	text := GenerateReport(report)
	t.Log("\n" + text)

	// Keep a baseline quality gate for the current rule-based engine.
	// This should be raised as patterns and semantic detection improve.
	const minAccuracy = 0.45
	if report.Metrics.Accuracy < minAccuracy {
		t.Errorf("accuracy %.1f%% is below %.0f%% threshold", report.Metrics.Accuracy*100, minAccuracy*100)
	}
}

func TestLoadSamples(t *testing.T) {
	malDir := filepath.Join("dataset", "malicious")
	if _, err := os.Stat(malDir); err != nil {
		t.Skipf("malicious dataset not found, skipping")
	}

	samples, err := LoadSamples(malDir)
	if err != nil {
		t.Fatalf("LoadSamples failed: %v", err)
	}

	if len(samples) == 0 {
		t.Fatal("expected malicious samples, got 0")
	}

	for _, s := range samples {
		if s.Label != "malicious" {
			t.Errorf("sample %s: expected label 'malicious', got %q", s.ID, s.Label)
		}
		if s.Content == "" {
			t.Errorf("sample %s: content is empty", s.ID)
		}
	}
}
