package engine

import (
	"fmt"
	"sort"
	"strings"
)

const (
	defaultMaxCustomScannerScore = 50
	customScannerMinScore        = 0
	customScannerMaxScore        = 100
	customScannerMinPriority     = 0
	customScannerMaxPriority     = 1000
	customPatternPrefix          = "custom-"
	pipelineEarlyExitScore       = 80
)

var scannerLayerExecutionOrder = []ScannerLayer{
	ScannerLayerHeuristics,
	ScannerLayerCustom,
	ScannerLayerVector,
	ScannerLayerLLM,
	ScannerLayerCanary,
}

// ExternalScanContext is the context exposed to custom scanner adapters.
type ExternalScanContext struct {
	Text         string
	RawText      string
	URL          string
	Mode         Mode
	IsOutputScan bool
	CurrentScore int
}

// ExternalScanResult is the result returned by custom scanner adapters.
type ExternalScanResult struct {
	Score     int
	Category  string
	Reason    string
	Matched   bool
	PatternID string
	Metadata  map[string]string
}

// ConfigScanner is the scanner interface accepted by engine config.
type ConfigScanner interface {
	Name() string
	Priority() int
	Scan(ctx ExternalScanContext) ExternalScanResult
}

type internalScanContext struct {
	Text         string
	RawText      string
	URL          string
	Mode         Mode
	IsOutputScan bool
	CurrentScore int
}

type internalScanResult struct {
	Score     int
	Category  string
	Reason    string
	Matched   bool
	PatternID string
	Metadata  map[string]string
}

type customScanResult struct {
	TotalScore  int
	Categories  []string
	Reasons     []string
	PatternIDs  []string
	Matched     bool
	ScannersRun int
}

// publicScanner is the engine-internal representation of custom scanners.
type publicScanner interface {
	Name() string
	Scan(ctx internalScanContext) internalScanResult
}

// internalScanner wraps a custom scanner for scoring and safety controls.
type internalScanner struct {
	scanner  publicScanner
	name     string
	priority int
	scoreCap int
}

// LayeredScanner wraps a scanner with its execution layer metadata.
type LayeredScanner struct {
	Layer   ScannerLayer
	Scanner internalScanner
}

type publicScannerAdapter struct {
	s ConfigScanner
}

func (a *publicScannerAdapter) Name() string {
	if a == nil || a.s == nil {
		return ""
	}
	return a.s.Name()
}

func (a *publicScannerAdapter) Scan(ctx internalScanContext) internalScanResult {
	if a == nil || a.s == nil {
		return internalScanResult{}
	}

	extCtx := ExternalScanContext(ctx)
	extResult := a.s.Scan(extCtx)
	result := internalScanResult(extResult)
	result.Metadata = cloneMetadata(result.Metadata)
	return result
}

func adaptPublicScanner(s ConfigScanner, scoreCap int) internalScanner {
	if scoreCap <= 0 {
		scoreCap = defaultMaxCustomScannerScore
	}

	name := ""
	if s != nil {
		name = strings.TrimSpace(s.Name())
	}

	return internalScanner{
		scanner:  &publicScannerAdapter{s: s},
		name:     name,
		priority: clampPriority(s.Priority()),
		scoreCap: scoreCap,
	}
}

func adaptConfiguredScanners(scanners []ConfigScanner, scoreCap int, layer ScannerLayer) []LayeredScanner {
	effectiveLayer := enforceCustomLayer(layer)
	out := make([]LayeredScanner, 0, len(scanners))
	for _, s := range scanners {
		if s == nil {
			continue
		}
		name := strings.TrimSpace(s.Name())
		if name == "" {
			continue
		}
		out = append(out, LayeredScanner{
			Layer:   effectiveLayer,
			Scanner: adaptPublicScanner(s, scoreCap),
		})
	}
	return out
}

// runCustomScanners executes all custom scanners and aggregates results.
func runCustomScanners(scanners []internalScanner, ctx internalScanContext) customScanResult {
	result := customScanResult{}
	if len(scanners) == 0 {
		return result
	}

	sorted := append([]internalScanner(nil), scanners...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].priority == sorted[j].priority {
			return false
		}
		return sorted[i].priority > sorted[j].priority
	})

	for _, s := range sorted {
		if s.scanner == nil || strings.TrimSpace(s.name) == "" {
			continue
		}
		result.ScannersRun++

		scanResult, err := safeRunScanner(s, ctx)
		if err != nil {
			continue
		}
		if !scanResult.Matched {
			continue
		}

		cappedScore := normalizeCustomScore(scanResult.Score)
		if cappedScore > s.scoreCap {
			cappedScore = s.scoreCap
		}
		if cappedScore > 0 {
			result.TotalScore += cappedScore
		}

		if cat := strings.TrimSpace(scanResult.Category); cat != "" {
			result.Categories = appendUniqueString(result.Categories, cat)
		}
		if reason := strings.TrimSpace(scanResult.Reason); reason != "" {
			result.Reasons = appendUniqueString(result.Reasons, reason)
		}

		patternID := strings.TrimSpace(scanResult.PatternID)
		if patternID == "" {
			patternID = customPatternPrefix + s.name
		}
		result.PatternIDs = appendUniqueString(result.PatternIDs, patternID)
		result.Matched = true
	}

	sort.Strings(result.Categories)
	sort.Strings(result.Reasons)
	sort.Strings(result.PatternIDs)

	return result
}

func runLayeredScanners(scanners []LayeredScanner, ctx internalScanContext, fullPipeline bool) (customScanResult, []LayerResult) {
	total := customScanResult{}
	if len(scanners) == 0 {
		return total, nil
	}

	layers := make([]LayerResult, 0, len(scannerLayerExecutionOrder))
	seenCats := make(map[string]struct{})
	seenReasons := make(map[string]struct{})
	seenPatterns := make(map[string]struct{})
	earlyExitTriggered := false

	for _, layer := range scannerLayerExecutionOrder {
		if layer == ScannerLayerHeuristics {
			continue
		}
		if earlyExitTriggered && layer != ScannerLayerCanary {
			continue
		}

		layerScanners := scannersForLayer(scanners, layer)
		if len(layerScanners) == 0 {
			continue
		}

		layerResult := runCustomScanners(layerScanners, ctx)
		if layerResult.Matched {
			total.Matched = true
			total.TotalScore += layerResult.TotalScore
			total.Categories = mergeUniqueStrings(total.Categories, layerResult.Categories)
			total.Reasons = mergeUniqueStrings(total.Reasons, layerResult.Reasons)
			total.PatternIDs = mergeUniqueStrings(total.PatternIDs, layerResult.PatternIDs)
		}
		total.ScannersRun += layerResult.ScannersRun

		layerCategories := dedupeAcrossLayer(layerResult.Categories, seenCats)
		layerReasons := dedupeAcrossLayer(layerResult.Reasons, seenReasons)
		layerPatterns := dedupeAcrossLayer(layerResult.PatternIDs, seenPatterns)

		layerReport := LayerResult{
			Layer:       layer,
			Score:       layerResult.TotalScore,
			ScannersRun: layerResult.ScannersRun,
			Matched:     layerResult.Matched,
			Categories:  layerCategories,
			Patterns:    layerPatterns,
			Reasons:     layerReasons,
		}

		if !fullPipeline && ctx.CurrentScore+total.TotalScore >= pipelineEarlyExitScore {
			layerReport.EarlyExit = true
			earlyExitTriggered = true
		}

		if !isEmptyLayerResult(layerReport) {
			layers = append(layers, layerReport)
		}
	}

	return total, layers
}

func scannersForLayer(scanners []LayeredScanner, layer ScannerLayer) []internalScanner {
	out := make([]internalScanner, 0, len(scanners))
	for _, s := range scanners {
		if s.Layer != layer {
			continue
		}
		out = append(out, s.Scanner)
	}
	return out
}

func heuristicLayerResult(result RiskResult) LayerResult {
	layer := LayerResult{
		Layer:       ScannerLayerHeuristics,
		Score:       result.Score,
		ScannersRun: 1,
		Matched:     result.Score > 0 || len(result.Patterns) > 0,
		Categories:  append([]string(nil), result.Categories...),
		Patterns:    append([]string(nil), result.Patterns...),
	}
	if strings.TrimSpace(result.Reason) != "" {
		layer.Reasons = []string{result.Reason}
	}
	layer.Categories = dedupeStrings(layer.Categories)
	layer.Patterns = dedupeStrings(layer.Patterns)
	layer.Reasons = dedupeStrings(layer.Reasons)
	return layer
}

func safeRunScanner(s internalScanner, ctx internalScanContext) (result internalScanResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("scanner %q panicked: %v", s.name, r)
			result = internalScanResult{}
		}
	}()

	result = s.scanner.Scan(ctx)
	return result, nil
}

func normalizeCustomScore(score int) int {
	if score < customScannerMinScore {
		return customScannerMinScore
	}
	if score > customScannerMaxScore {
		return customScannerMaxScore
	}
	return score
}

func appendUniqueString(values []string, value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return values
	}
	for _, existing := range values {
		if existing == trimmed {
			return values
		}
	}
	return append(values, trimmed)
}

func clampPriority(priority int) int {
	if priority < customScannerMinPriority {
		return customScannerMinPriority
	}
	if priority > customScannerMaxPriority {
		return customScannerMaxPriority
	}
	return priority
}

func enforceCustomLayer(layer ScannerLayer) ScannerLayer {
	if layer == ScannerLayerCustom {
		return layer
	}
	return ScannerLayerCustom
}

func cloneMetadata(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func dedupeAcrossLayer(values []string, seen map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isEmptyLayerResult(layer LayerResult) bool {
	if layer.Score != 0 {
		return false
	}
	if layer.Matched {
		return false
	}
	if layer.EarlyExit {
		return false
	}
	return len(layer.Categories) == 0 && len(layer.Patterns) == 0 && len(layer.Reasons) == 0
}
