package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/domain/alert"
	"github.com/javiyt/safeops-mcp/internal/domain/audit"
	"github.com/javiyt/safeops-mcp/internal/ports"
	"github.com/javiyt/safeops-mcp/internal/redaction"
)

var auditSequence uint64

type Notifier interface {
	Notify(ctx context.Context, message string) error
}

type Service struct {
	Config   config.Config
	Executor ports.ExecutorClient
	Alerts   ports.AlertRepository
	Audit    ports.AuditRepository
	Notifier Notifier
	Clock    ports.Clock
	Logger   *slog.Logger
}

type ListInput struct {
	Status   string `json:"status"`
	Severity string `json:"severity"`
	Limit    int    `json:"limit"`
}

type AcknowledgeInput struct {
	AlertID string `json:"alert_id"`
}

type SilenceInput struct {
	AlertID  string `json:"alert_id"`
	Duration string `json:"duration"`
}

func (s Service) RunOnce(ctx context.Context) error {
	now := s.now()
	if _, err := s.Alerts.PruneResolvedAlerts(ctx, now.Add(-s.Config.Alerts.Retention.Std())); err != nil {
		return err
	}
	findings := s.collectFindings(ctx)
	observed := map[string]bool{}
	var notify []alert.Alert
	for _, finding := range findings {
		a, _, err := s.Alerts.UpsertObserved(ctx, finding, now)
		if err != nil {
			return err
		}
		observed[a.ID] = true
		if s.shouldNotify(a, now) {
			notify = append(notify, a)
		}
	}
	resolved, err := s.Alerts.ResolveMissing(ctx, observed, now)
	if err != nil {
		return err
	}
	if s.Config.Alerts.NotifyResolution {
		for _, a := range resolved {
			if a.LastNotified != nil {
				notify = append(notify, a)
			}
		}
	}
	if len(notify) > 0 {
		if err := s.notify(ctx, notify, now); err != nil {
			return err
		}
	}
	return nil
}

func (s Service) ListAlerts(ctx context.Context, input ListInput) ([]alert.Alert, error) {
	return s.Alerts.ListAlerts(ctx, alert.ListFilter{Status: alert.Status(input.Status), Severity: alert.Severity(input.Severity)}, input.Limit)
}

func (s Service) AcknowledgeAlert(ctx context.Context, userID string, input AcknowledgeInput) (map[string]string, error) {
	a, err := s.Alerts.AcknowledgeAlert(ctx, input.AlertID, userID, s.now())
	if err != nil {
		return nil, err
	}
	if err := s.audit(ctx, userID, "alert_acknowledged", a.ID, "acknowledged", ""); err != nil {
		return nil, err
	}
	return map[string]string{"status": string(a.Status), "message": "Alert " + a.ID + " acknowledged."}, nil
}

func (s Service) SilenceAlert(ctx context.Context, userID string, input SilenceInput) (map[string]string, error) {
	d, err := time.ParseDuration(input.Duration)
	if err != nil || d <= 0 {
		return nil, fmt.Errorf("duration must be a positive Go duration such as 1h")
	}
	now := s.now()
	until := now.Add(d)
	a, err := s.Alerts.SilenceAlert(ctx, input.AlertID, until, now)
	if err != nil {
		return nil, err
	}
	if err := s.audit(ctx, userID, "alert_silenced", a.ID, "suppressed", ""); err != nil {
		return nil, err
	}
	return map[string]string{"status": string(a.Status), "message": fmt.Sprintf("Alert %s silenced until %s.", a.ID, until.UTC().Format(time.RFC3339))}, nil
}

func (s Service) ResolveAlert(ctx context.Context, userID, id string) (map[string]string, error) {
	a, err := s.Alerts.ResolveAlert(ctx, id, s.now())
	if err != nil {
		return nil, err
	}
	if err := s.audit(ctx, userID, "alert_resolved_manual", a.ID, "resolved", ""); err != nil {
		return nil, err
	}
	return map[string]string{"status": string(a.Status), "message": "Alert " + a.ID + " resolved."}, nil
}

func (s Service) collectFindings(ctx context.Context) []alert.Finding {
	var findings []alert.Finding
	if s.Config.Alerts.Checks.Services.Enabled {
		findings = append(findings, s.checkServices(ctx)...)
	}
	if s.Config.Podman.Enabled && s.Config.Alerts.Checks.Containers.Enabled {
		findings = append(findings, s.checkContainers(ctx)...)
	}
	if s.Config.Alerts.Checks.Executor.Enabled {
		findings = append(findings, s.checkExecutor(ctx)...)
	}
	if s.Config.Alerts.Checks.SQLite.Enabled {
		findings = append(findings, s.checkSQLite(ctx)...)
	}
	if s.Config.Alerts.Checks.CPU.Enabled {
		findings = append(findings, s.checkCPU(ctx)...)
	}
	if s.Config.Alerts.Checks.Memory.Enabled {
		findings = append(findings, s.checkMemory(ctx)...)
	}
	if s.Config.Alerts.Checks.Disk.Enabled {
		findings = append(findings, s.checkDisk(ctx)...)
	}
	if s.Config.Alerts.Checks.AppErrors.Enabled {
		findings = append(findings, s.checkAppErrors(ctx)...)
	}
	return findings
}

func (s Service) checkServices(ctx context.Context) []alert.Finding {
	var findings []alert.Finding
	aliases := sortedKeys(s.Config.Services)
	for _, alias := range aliases {
		st, err := s.Executor.ServiceStatus(ctx, alias)
		if err != nil {
			findings = append(findings, newFinding("service", alias, "service_status_unavailable", alert.SeverityWarning, "Service "+alias+" status could not be read.", err.Error()))
			continue
		}
		if st.ActiveState != "active" {
			findings = append(findings, newFinding("service", alias, "service_stopped", alert.SeverityCritical, "Service "+alias+" is "+safeState(st.ActiveState)+".", st.SubState))
		}
	}
	return findings
}

func (s Service) checkContainers(ctx context.Context) []alert.Finding {
	var findings []alert.Finding
	aliases := sortedKeys(s.Config.Containers)
	for _, alias := range aliases {
		st, err := s.Executor.ContainerStatus(ctx, alias)
		if err != nil {
			findings = append(findings, newFinding("container", alias, "container_status_unavailable", alert.SeverityWarning, "Container "+alias+" status could not be read.", err.Error()))
			continue
		}
		if !st.Exists || st.State != "running" {
			findings = append(findings, newFinding("container", alias, "container_down", alert.SeverityCritical, "Container "+alias+" is "+safeState(st.State)+".", st.Error))
			continue
		}
		if st.Health == "unhealthy" {
			findings = append(findings, newFinding("container", alias, "container_health_unhealthy", alert.SeverityCritical, "Container "+alias+" health check is unhealthy.", st.Health))
		}
	}
	return findings
}

func (s Service) checkExecutor(ctx context.Context) []alert.Finding {
	if _, err := s.Executor.SystemStatus(ctx); err != nil {
		return []alert.Finding{newFinding("system", "executor", "executor_unavailable", alert.SeverityCritical, "SafeOps executor is unavailable.", err.Error())}
	}
	return nil
}

func (s Service) checkSQLite(ctx context.Context) []alert.Finding {
	if err := s.Alerts.CheckAlertStorage(ctx, s.now()); err != nil {
		return []alert.Finding{newFinding("system", "sqlite", "sqlite_unwritable", alert.SeverityCritical, "SafeOps alert database is not writable.", err.Error())}
	}
	return nil
}

func (s Service) checkCPU(ctx context.Context) []alert.Finding {
	st, err := s.Executor.CPUStatus(ctx)
	if err != nil {
		return []alert.Finding{newFinding("system", "cpu", "cpu_status_unavailable", alert.SeverityWarning, "CPU status could not be read.", err.Error())}
	}
	var findings []alert.Finding
	if len(st.LoadAverage) > 0 {
		load := st.LoadAverage[0]
		if load >= s.Config.Alerts.Checks.CPU.LoadCritical {
			findings = append(findings, newFinding("system", "cpu", "cpu_load_high", alert.SeverityCritical, fmt.Sprintf("CPU load is %.2f.", load), fmt.Sprintf(`{"load":%.2f}`, load)))
		} else if load >= s.Config.Alerts.Checks.CPU.LoadWarning {
			findings = append(findings, newFinding("system", "cpu", "cpu_load_high", alert.SeverityWarning, fmt.Sprintf("CPU load is %.2f.", load), fmt.Sprintf(`{"load":%.2f}`, load)))
		}
	}
	if st.Temperature != nil {
		temp := *st.Temperature
		if temp >= s.Config.Alerts.Checks.CPU.TemperatureCritical {
			findings = append(findings, newFinding("system", "cpu", "cpu_temperature_high", alert.SeverityCritical, fmt.Sprintf("CPU temperature is %.1fC.", temp), fmt.Sprintf(`{"temperature":%.1f}`, temp)))
		} else if temp >= s.Config.Alerts.Checks.CPU.TemperatureWarning {
			findings = append(findings, newFinding("system", "cpu", "cpu_temperature_high", alert.SeverityWarning, fmt.Sprintf("CPU temperature is %.1fC.", temp), fmt.Sprintf(`{"temperature":%.1f}`, temp)))
		}
	}
	return findings
}

func (s Service) checkMemory(ctx context.Context) []alert.Finding {
	st, err := s.Executor.MemoryStatus(ctx)
	if err != nil {
		return []alert.Finding{newFinding("system", "memory", "memory_status_unavailable", alert.SeverityWarning, "Memory status could not be read.", err.Error())}
	}
	if st.MemoryPressure >= s.Config.Alerts.Checks.Memory.PressureCritical {
		return []alert.Finding{newFinding("system", "memory", "memory_pressure_high", alert.SeverityCritical, fmt.Sprintf("Memory pressure is %.2f.", st.MemoryPressure), fmt.Sprintf(`{"pressure":%.2f}`, st.MemoryPressure))}
	}
	if st.MemoryPressure >= s.Config.Alerts.Checks.Memory.PressureWarning {
		return []alert.Finding{newFinding("system", "memory", "memory_pressure_high", alert.SeverityWarning, fmt.Sprintf("Memory pressure is %.2f.", st.MemoryPressure), fmt.Sprintf(`{"pressure":%.2f}`, st.MemoryPressure))}
	}
	if len(st.OOMEvents) > 0 {
		return []alert.Finding{newFinding("system", "memory", "oom_recent", alert.SeverityCritical, "Recent OOM events were reported.", fmt.Sprintf(`{"events":%d}`, len(st.OOMEvents)))}
	}
	return nil
}

func (s Service) checkDisk(ctx context.Context) []alert.Finding {
	st, err := s.Executor.DiskHealth(ctx, "")
	if err != nil {
		return []alert.Finding{newFinding("disk", "all", "disk_status_unavailable", alert.SeverityWarning, "Disk health could not be read.", err.Error())}
	}
	var findings []alert.Finding
	for _, disk := range st.Disks {
		alias := disk.Name
		if disk.UsagePercent >= s.Config.Alerts.Checks.Disk.Critical {
			findings = append(findings, newFinding("disk", alias, "disk_usage_high", alert.SeverityCritical, fmt.Sprintf("Disk %s usage is %.1f percent.", alias, disk.UsagePercent), fmt.Sprintf(`{"usage_percent":%.1f}`, disk.UsagePercent)))
		} else if disk.UsagePercent >= s.Config.Alerts.Checks.Disk.Warning {
			findings = append(findings, newFinding("disk", alias, "disk_usage_high", alert.SeverityWarning, fmt.Sprintf("Disk %s usage is %.1f percent.", alias, disk.UsagePercent), fmt.Sprintf(`{"usage_percent":%.1f}`, disk.UsagePercent)))
		}
	}
	return findings
}

func (s Service) checkAppErrors(ctx context.Context) []alert.Finding {
	pattern, err := regexp.Compile(s.Config.Alerts.Checks.AppErrors.Pattern)
	if err != nil {
		return []alert.Finding{newFinding("system", "app_errors", "app_error_pattern_invalid", alert.SeverityWarning, "Application error alert pattern is invalid.", err.Error())}
	}
	var findings []alert.Finding
	for _, alias := range sortedKeys(s.Config.Services) {
		logs, err := s.Executor.ServiceLogs(ctx, ports.ServiceLogsRequest{Service: alias, Lines: s.Config.Limits.MaxLogLines, Priority: "err", Since: "15m"})
		if err != nil {
			continue
		}
		count := countMatches(pattern, serviceLogMessages(logs))
		if count >= s.Config.Alerts.Checks.AppErrors.Threshold {
			findings = append(findings, newFinding("service", alias, "application_errors_repeated", alert.SeverityWarning, fmt.Sprintf("Service %s has %d recent error log entries.", alias, count), fmt.Sprintf(`{"count":%d}`, count)))
		}
	}
	if s.Config.Podman.Enabled {
		for _, alias := range sortedKeys(s.Config.Containers) {
			logs, err := s.Executor.ContainerLogs(ctx, ports.ContainerLogsRequest{Container: alias, Lines: s.Config.Limits.MaxLogLines, Since: "15m"})
			if err != nil {
				continue
			}
			count := countMatches(pattern, containerLogMessages(logs))
			if count >= s.Config.Alerts.Checks.AppErrors.Threshold {
				findings = append(findings, newFinding("container", alias, "application_errors_repeated", alert.SeverityWarning, fmt.Sprintf("Container %s has %d recent error log entries.", alias, count), fmt.Sprintf(`{"count":%d}`, count)))
			}
		}
	}
	return findings
}

func (s Service) shouldNotify(a alert.Alert, now time.Time) bool {
	if a.Status == alert.StatusSuppressed && a.SuppressedUntil != nil && now.Before(*a.SuppressedUntil) {
		return false
	}
	if inSilenceSchedule(s.Config.Alerts.SilenceSchedule, now) {
		return false
	}
	if now.Sub(a.FirstObserved) < s.Config.Alerts.PersistenceThreshold.Std() {
		return false
	}
	if a.LastNotified != nil && now.Sub(*a.LastNotified) < s.Config.Alerts.Cooldown.Std() {
		return false
	}
	return true
}

func (s Service) notify(ctx context.Context, alerts []alert.Alert, now time.Time) error {
	if s.Notifier == nil {
		return nil
	}
	msg := formatNotification(alerts)
	if err := s.Notifier.Notify(ctx, msg); err != nil {
		return err
	}
	for _, a := range alerts {
		if err := s.Alerts.MarkAlertNotified(ctx, a.ID, now); err != nil {
			return err
		}
		if err := s.audit(ctx, "system", "alert_notification_sent", a.ID, string(a.Status), ""); err != nil {
			return err
		}
	}
	return nil
}

func (s Service) audit(ctx context.Context, userID, eventType, action, status, errSummary string) error {
	if s.Audit == nil {
		return nil
	}
	return s.Audit.Append(ctx, audit.Event{
		ID:             fmt.Sprintf("aud_%d_%d", s.now().UnixNano(), atomic.AddUint64(&auditSequence, 1)),
		Timestamp:      s.now(),
		UserID:         userID,
		Component:      "safeops-monitor",
		EventType:      eventType,
		Tool:           "alerts",
		Action:         action,
		Arguments:      "{}",
		Risk:           "read",
		PolicyDecision: "allow",
		Status:         status,
		ErrorSummary:   redaction.Redact(errSummary),
	})
}

func (s Service) now() time.Time {
	if s.Clock == nil {
		return time.Now().UTC()
	}
	return s.Clock.Now().UTC()
}

func newFinding(kind, alias, typ string, severity alert.Severity, message, metadata string) alert.Finding {
	if metadata != "" && !json.Valid([]byte(metadata)) {
		metadata = fmt.Sprintf(`{"detail":%q}`, redaction.Redact(metadata))
	}
	return alert.Finding{ResourceKind: kind, ResourceAlias: alias, Type: typ, Severity: severity, Message: redaction.Redact(message), Metadata: metadata}
}

func formatNotification(alerts []alert.Alert) string {
	if len(alerts) == 1 {
		a := alerts[0]
		if a.Status == alert.StatusResolved {
			return fmt.Sprintf("Resolved: %s (%s/%s).", a.Message, a.ResourceKind, a.ResourceAlias)
		}
		return fmt.Sprintf("Alert: %s\nSeverity: %s\nID: %s\nNo action has been taken.", a.Message, a.Severity, a.ID)
	}
	lines := []string{fmt.Sprintf("Alerts: %d alerts require attention.", len(alerts))}
	for _, a := range alerts {
		lines = append(lines, fmt.Sprintf("- %s: %s (%s)", a.ID, a.Message, a.Severity))
	}
	lines = append(lines, "No action has been taken.")
	return strings.Join(lines, "\n")
}

func inSilenceSchedule(windows []config.SilenceScheduleConfig, now time.Time) bool {
	for _, window := range windows {
		loc := time.Local
		if window.Timezone != "" {
			loaded, err := time.LoadLocation(window.Timezone)
			if err == nil {
				loc = loaded
			}
		}
		local := now.In(loc)
		start, _ := time.Parse("15:04", window.Start)
		end, _ := time.Parse("15:04", window.End)
		currentMinutes := local.Hour()*60 + local.Minute()
		startMinutes := start.Hour()*60 + start.Minute()
		endMinutes := end.Hour()*60 + end.Minute()
		if startMinutes <= endMinutes && currentMinutes >= startMinutes && currentMinutes < endMinutes {
			return true
		}
		if startMinutes > endMinutes && (currentMinutes >= startMinutes || currentMinutes < endMinutes) {
			return true
		}
	}
	return false
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func safeState(state string) string {
	if strings.TrimSpace(state) == "" {
		return "unknown"
	}
	return redaction.Redact(state)
}

func serviceLogMessages(logs ports.ServiceLogsResponse) []string {
	out := make([]string, 0, len(logs.Entries))
	for _, entry := range logs.Entries {
		out = append(out, entry.Message)
	}
	return out
}

func containerLogMessages(logs ports.ContainerLogsResponse) []string {
	out := make([]string, 0, len(logs.Entries))
	for _, entry := range logs.Entries {
		out = append(out, entry.Message)
	}
	return out
}

func countMatches(pattern *regexp.Regexp, lines []string) int {
	count := 0
	for _, line := range lines {
		if pattern.MatchString(line) {
			count++
		}
	}
	return count
}
