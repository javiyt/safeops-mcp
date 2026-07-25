package action

type Risk string

const (
	RiskRead        Risk = "read"
	RiskMutating    Risk = "mutating"
	RiskDestructive Risk = "destructive"
)

type Type string

const (
	TypeRestartService Type = "restart_service"
)
