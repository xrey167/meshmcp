package harness

// Mode selects which pipeline states run and how aggressively the scheduler
// parallelizes. Merged from the source harnesses' modes. A caller requests a
// mode but policy CLAMPS it (ClampMode): a low-trust identity may be denied
// ultrawork's fan-out budget even if it asks for it.
type Mode string

const (
	ModeQuick         Mode = "quick"          // single executor, skip interview/plan-review
	ModeTeam          Mode = "team"           // full pipeline, bounded parallel workers
	ModeAutopilot     Mode = "autopilot"      // autonomous; interview→settle, pauses only for co-sign
	ModeRalph         Mode = "ralph"          // persistent verify/fix loop until goal met or budget out
	ModeUltrawork     Mode = "ultrawork"      // max parallel exploration + execution
	ModeSynthesize    Mode = "synthesize"     // run N providers on one task, merge best
	ModeInterviewOnly Mode = "interview-only" // stop after the requirements artifact
	ModePlanOnly      Mode = "plan-only"      // stop after an approved plan
)

// KnownMode reports whether m is a canonical mode.
func KnownMode(m Mode) bool {
	switch m {
	case ModeQuick, ModeTeam, ModeAutopilot, ModeRalph, ModeUltrawork,
		ModeSynthesize, ModeInterviewOnly, ModePlanOnly:
		return true
	}
	return false
}

// Stage is one state of the merged pipeline (§5.2).
type Stage string

const (
	StageIntake     Stage = "intake"
	StageInterview  Stage = "interview"
	StagePlan       Stage = "plan"
	StagePlanReview Stage = "plan-review"
	StageApprove    Stage = "approve"
	StageExecute    Stage = "execute"
	StageVerify     Stage = "verify"
	StageFix        Stage = "fix"
	StageSettle     Stage = "settle"
)

// pipelineOrder is the canonical stage order the orchestrator advances through.
var pipelineOrder = []Stage{
	StageIntake, StageInterview, StagePlan, StagePlanReview,
	StageApprove, StageExecute, StageVerify, StageFix, StageSettle,
}

// stagesFor returns the ordered stages a mode runs. Stages a mode skips are
// omitted; the orchestrator advances only through the returned set.
func stagesFor(m Mode) []Stage {
	switch m {
	case ModeQuick:
		// single executor; skip interview and plan-review
		return []Stage{StageIntake, StagePlan, StageApprove, StageExecute, StageVerify, StageSettle}
	case ModeInterviewOnly:
		return []Stage{StageIntake, StageInterview, StageSettle}
	case ModePlanOnly:
		return []Stage{StageIntake, StageInterview, StagePlan, StagePlanReview, StageSettle}
	case ModeSynthesize:
		return []Stage{StageIntake, StageExecute, StageVerify, StageSettle}
	case ModeAutopilot, ModeRalph, ModeUltrawork, ModeTeam:
		return pipelineOrder
	default:
		return pipelineOrder
	}
}

// loopKindFor returns the loop driver a mode uses, or "" for a single pass.
func loopKindFor(m Mode) LoopKind {
	switch m {
	case ModeRalph:
		return LoopRalph
	case ModeUltrawork:
		return LoopUltrawork
	case ModeAutopilot:
		return LoopAutopilot
	default:
		return ""
	}
}
