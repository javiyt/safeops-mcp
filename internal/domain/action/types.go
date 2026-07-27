package action

type Risk string

const (
	RiskRead        Risk = "read"
	RiskMutating    Risk = "mutating"
	RiskDestructive Risk = "destructive"
)

type Type string

const (
	TypeRestartService   Type = "restart_service"
	TypeRestartContainer Type = "restart_container"
	TypeRestartGroup     Type = "restart_group"
	TypeRotateLogs       Type = "rotate_logs"
	TypeCleanupCache     Type = "cleanup_cache"
	TypeRemoveRecords    Type = "remove_records"
	TypeResetFailure     Type = "reset_failure"
	TypeRebootHost       Type = "reboot_host"
)

type ResourceKind string

const (
	ResourceService      ResourceKind = "service"
	ResourceContainer    ResourceKind = "container"
	ResourceGroup        ResourceKind = "group"
	ResourceLog          ResourceKind = "log"
	ResourceCache        ResourceKind = "cache"
	ResourceRecord       ResourceKind = "record"
	ResourceFailureState ResourceKind = "failure_state"
	ResourceHost         ResourceKind = "host"
)
