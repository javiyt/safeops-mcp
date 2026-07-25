package policy

import (
	"testing"

	"github.com/javiyt/safeops-mcp/internal/domain/action"
)

func TestDecide(t *testing.T) {
	engine := Engine{}
	if engine.Decide(action.RiskRead) != DecisionAllow {
		t.Fatal("read risk should be allowed")
	}
	if engine.Decide(action.RiskMutating) != DecisionRequireApproval {
		t.Fatal("mutating risk should require approval")
	}
	if engine.Decide(action.RiskDestructive) != DecisionDeny {
		t.Fatal("destructive risk should be denied")
	}
	if engine.Decide("unknown") != DecisionDeny {
		t.Fatal("unknown risk should be denied")
	}
}
