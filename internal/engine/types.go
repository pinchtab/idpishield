package engine

import "github.com/pinchtab/idpishield/internal/types"

// Type aliases — engine uses types from internal/types.
type Mode = types.Mode

const (
	ModeFast     = types.ModeFast
	ModeBalanced = types.ModeBalanced
	ModeDeep     = types.ModeDeep
)

type RiskResult = types.RiskResult
type Intent = types.Intent

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
