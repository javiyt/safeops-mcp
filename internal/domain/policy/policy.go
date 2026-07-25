package policy

import "github.com/javiyt/safeops-mcp/internal/domain/action"

type Decision string

const (
	DecisionAllow           Decision = "allow"
	DecisionDeny            Decision = "deny"
	DecisionRequireApproval Decision = "require_approval"
)

type Engine struct {
	DryRun bool
}

func (e Engine) Decide(risk action.Risk) Decision {
	switch risk {
	case action.RiskRead:
		return DecisionAllow
	case action.RiskMutating:
		return DecisionRequireApproval
	case action.RiskDestructive:
		return DecisionDeny
	default:
		return DecisionDeny
	}
}
