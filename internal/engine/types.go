package engine

import "github.com/pinchtab/idpishield/internal/types"

// Type aliases — engine uses types from internal/types.
type Mode = types.Mode

const (
	ModeFast     = types.ModeFast
	ModeBalanced = types.ModeBalanced
	ModeDeep     = types.ModeDeep
	ModeStrict   = types.ModeStrict
)

type RiskResult = types.RiskResult
type JudgeVerdictResult = types.JudgeVerdictResult
type Intent = types.Intent
type ScannerLayer = types.ScannerLayer
type LayerResult = types.LayerResult

const (
	ScannerLayerHeuristics = types.ScannerLayerHeuristics
	ScannerLayerCustom     = types.ScannerLayerCustom
	ScannerLayerVector     = types.ScannerLayerVector
	ScannerLayerLLM        = types.ScannerLayerLLM
	ScannerLayerCanary     = types.ScannerLayerCanary
)

const (
	IntentNone              = types.IntentNone
	IntentInstructionBypass = types.IntentInstructionBypass
	IntentDataExfiltration  = types.IntentDataExfiltration
	IntentDataDestruction   = types.IntentDataDestruction
	IntentUnauthorizedTx    = types.IntentUnauthorizedTx
	IntentJailbreak         = types.IntentJailbreak
	IntentOutputSteering    = types.IntentOutputSteering
	IntentSystemCompromise  = types.IntentSystemCompromise
	IntentResourceExhaust   = types.IntentResourceExhaust
	IntentAgentHijacking    = types.IntentAgentHijacking
)

var (
	ParseMode       = types.ParseMode
	ParseModeStrict = types.ParseModeStrict
	ScoreToLevel    = types.ScoreToLevel
	ShouldBlock     = types.ShouldBlock
	SafeResult      = types.SafeResult
)

// assessmentContext carries internal score composition for debias decisions.
type assessmentContext struct {
	TriggerOnlyScore  int
	InjectionScore    int
	DebiasExplanation string
	HasBanListMatch   bool
}
