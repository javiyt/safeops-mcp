package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server      ServerConfig               `yaml:"server"`
	Identity    IdentityConfig             `yaml:"identity"`
	Database    DatabaseConfig             `yaml:"database"`
	Socket      SocketConfig               `yaml:"socket"`
	Policies    PoliciesConfig             `yaml:"policies"`
	Limits      LimitsConfig               `yaml:"limits"`
	Filesystem  FilesystemConfig           `yaml:"filesystem"`
	Diagnostics DiagnosticsConfig          `yaml:"diagnostics"`
	Alerts      AlertsConfig               `yaml:"alerts"`
	Telegram    TelegramConfig             `yaml:"telegram"`
	Services    map[string]ServiceConfig   `yaml:"services"`
	Podman      PodmanConfig               `yaml:"podman"`
	Containers  map[string]ContainerConfig `yaml:"containers"`
}

type ServerConfig struct {
	Name string `yaml:"name"`
}

type IdentityConfig struct {
	AdministratorID string `yaml:"administrator_id"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type SocketConfig struct {
	Path  string `yaml:"path"`
	Group string `yaml:"group"`
	Mode  string `yaml:"mode"`
}

type PoliciesConfig struct {
	Default            string   `yaml:"default"`
	DestructiveActions string   `yaml:"destructive_actions"`
	ApprovalExpiration Duration `yaml:"approval_expiration"`
	DryRun             bool     `yaml:"dry_run"`
}

type LimitsConfig struct {
	OperationTimeout       Duration `yaml:"operation_timeout"`
	MaxLogLines            int      `yaml:"max_log_lines"`
	MaxToolOutputBytes     int      `yaml:"max_tool_output_bytes"`
	MaxHealthcheckAttempts int      `yaml:"max_healthcheck_attempts"`
}

type FilesystemConfig struct {
	DiskPaths map[string]DiskPathConfig `yaml:"disk_paths"`
}

type DiagnosticsConfig struct {
	CPU     DiagnosticsCPUConfig     `yaml:"cpu"`
	Memory  DiagnosticsMemoryConfig  `yaml:"memory"`
	Disk    DiagnosticsDiskConfig    `yaml:"disk"`
	Network DiagnosticsNetworkConfig `yaml:"network"`
	Time    DiagnosticsTimeConfig    `yaml:"time"`
}

type DiagnosticsCPUConfig struct {
	LoadWarning         float64 `yaml:"load_warning"`
	LoadCritical        float64 `yaml:"load_critical"`
	TemperatureWarning  float64 `yaml:"temperature_warning"`
	TemperatureCritical float64 `yaml:"temperature_critical"`
}

type DiagnosticsMemoryConfig struct {
	AvailableWarningPercent  float64 `yaml:"available_warning_percent"`
	AvailableCriticalPercent float64 `yaml:"available_critical_percent"`
	SwapWarning              float64 `yaml:"swap_warning"`
	OOMCheck                 bool    `yaml:"oom_check"`
}

type DiagnosticsDiskConfig struct {
	UsageWarning  float64 `yaml:"usage_warning"`
	UsageCritical float64 `yaml:"usage_critical"`
	InodeWarning  float64 `yaml:"inode_warning"`
	InodeCritical float64 `yaml:"inode_critical"`
	SMARTCheck    bool    `yaml:"smart_check"`
}

type DiagnosticsNetworkConfig struct {
	PingTargets    []string `yaml:"ping_targets"`
	LatencyWarning Duration `yaml:"latency_warning"`
	RedactIPs      bool     `yaml:"redact_ips"`
}

type DiagnosticsTimeConfig struct {
	NTPCheck     bool     `yaml:"ntp_check"`
	DriftWarning Duration `yaml:"drift_warning"`
}

type AlertsConfig struct {
	Enabled              bool                    `yaml:"enabled"`
	Interval             Duration                `yaml:"interval"`
	Cooldown             Duration                `yaml:"cooldown"`
	PersistenceThreshold Duration                `yaml:"persistence_threshold"`
	NotifyResolution     bool                    `yaml:"notify_resolution"`
	Retention            Duration                `yaml:"retention"`
	Telegram             AlertsTelegramConfig    `yaml:"telegram"`
	SilenceSchedule      []SilenceScheduleConfig `yaml:"silence_schedule"`
	Checks               AlertChecksConfig       `yaml:"checks"`
}

type AlertsTelegramConfig struct {
	Enabled bool  `yaml:"enabled"`
	ChatID  int64 `yaml:"chat_id"`
}

type SilenceScheduleConfig struct {
	Start    string `yaml:"start"`
	End      string `yaml:"end"`
	Timezone string `yaml:"timezone"`
}

type AlertChecksConfig struct {
	Services     AlertCheckConfig             `yaml:"services"`
	Containers   AlertCheckConfig             `yaml:"containers"`
	Disk         AlertThresholdCheckConfig    `yaml:"disk"`
	Memory       AlertMemoryCheckConfig       `yaml:"memory"`
	CPU          AlertCPUCheckConfig          `yaml:"cpu"`
	SQLite       AlertCheckConfig             `yaml:"sqlite"`
	Executor     AlertCheckConfig             `yaml:"executor"`
	AppErrors    AlertAppErrorsCheckConfig    `yaml:"app_errors"`
	Certificates AlertCertificatesCheckConfig `yaml:"certificates"`
	Backups      AlertBackupsCheckConfig      `yaml:"backups"`
}

type AlertCheckConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Interval Duration `yaml:"interval"`
}

type AlertThresholdCheckConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Interval Duration `yaml:"interval"`
	Warning  float64  `yaml:"warning"`
	Critical float64  `yaml:"critical"`
}

type AlertMemoryCheckConfig struct {
	Enabled          bool     `yaml:"enabled"`
	Interval         Duration `yaml:"interval"`
	PressureWarning  float64  `yaml:"pressure_warning"`
	PressureCritical float64  `yaml:"pressure_critical"`
}

type AlertCPUCheckConfig struct {
	Enabled             bool     `yaml:"enabled"`
	Interval            Duration `yaml:"interval"`
	LoadWarning         float64  `yaml:"load_warning"`
	LoadCritical        float64  `yaml:"load_critical"`
	TemperatureWarning  float64  `yaml:"temperature_warning"`
	TemperatureCritical float64  `yaml:"temperature_critical"`
}

type AlertAppErrorsCheckConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Interval  Duration `yaml:"interval"`
	Pattern   string   `yaml:"pattern"`
	Threshold int      `yaml:"threshold"`
}

type AlertCertificatesCheckConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Interval     Duration `yaml:"interval"`
	WarningDays  int      `yaml:"warning_days"`
	CriticalDays int      `yaml:"critical_days"`
}

type AlertBackupsCheckConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Interval Duration `yaml:"interval"`
	MaxAge   Duration `yaml:"max_age"`
}

type DiskPathConfig struct {
	Path string `yaml:"path"`
}

type ServiceConfig struct {
	Unit        string             `yaml:"unit"`
	Permissions PermissionsConfig  `yaml:"permissions"`
	Healthcheck *HealthcheckConfig `yaml:"healthcheck,omitempty"`
}

type PermissionsConfig struct {
	Status  string `yaml:"status"`
	Logs    string `yaml:"logs"`
	Restart string `yaml:"restart"`
}

type HealthcheckConfig struct {
	URL      string   `yaml:"url"`
	Timeout  Duration `yaml:"timeout"`
	Attempts int      `yaml:"attempts"`
	Interval Duration `yaml:"interval"`
}

type PodmanConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Binary       string `yaml:"binary"`
	Mode         string `yaml:"mode"`
	SystemdScope string `yaml:"systemd_scope"`
}

type ContainerConfig struct {
	ContainerName string                `yaml:"container_name"`
	Management    string                `yaml:"management"`
	QuadletUnit   string                `yaml:"quadlet_unit"`
	Permissions   PermissionsConfig     `yaml:"permissions"`
	Logs          ContainerLogsConfig   `yaml:"logs"`
	Health        ContainerHealthConfig `yaml:"health"`
}

type ContainerLogsConfig struct {
	MaxLines int `yaml:"max_lines"`
}

type ContainerHealthConfig struct {
	RequireHealthyAfterRestart bool     `yaml:"require_healthy_after_restart"`
	Attempts                   int      `yaml:"attempts"`
	Interval                   Duration `yaml:"interval"`
}

type TelegramConfig struct {
	Enabled          bool                       `yaml:"enabled"`
	Token            string                     `yaml:"token"`
	TokenEnv         string                     `yaml:"token_env"`
	AllowedUsers     []int64                    `yaml:"allowed_users"`
	AdminID          int64                      `yaml:"admin_id"`
	RateLimit        TelegramRateLimitConfig    `yaml:"rate_limit"`
	MessageSizeLimit int                        `yaml:"message_size_limit"`
	Confirmation     TelegramConfirmationConfig `yaml:"confirmation"`
	Buttons          TelegramButtonsConfig      `yaml:"buttons"`
	OpenClaw         TelegramOpenClawConfig     `yaml:"openclaw"`
}

type TelegramRateLimitConfig struct {
	MessagesPerMinute int `yaml:"messages_per_minute"`
}

type TelegramConfirmationConfig struct {
	CodeLength        int `yaml:"code_length"`
	ExpirationSeconds int `yaml:"expiration_seconds"`
}

type TelegramButtonsConfig struct {
	Enabled bool `yaml:"enabled"`
}

type TelegramOpenClawConfig struct {
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
	Timeout Duration `yaml:"timeout"`
}

type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer func() {
		_ = f.Close()
	}()
	decoder := yaml.NewDecoder(f)
	decoder.KnownFields(true)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	cfg.ApplyDefaults()
	return cfg, Validate(cfg)
}

func (cfg *Config) ApplyDefaults() {
	if cfg.Diagnostics.CPU.LoadWarning == 0 {
		cfg.Diagnostics.CPU.LoadWarning = 2.0
	}
	if cfg.Diagnostics.CPU.LoadCritical == 0 {
		cfg.Diagnostics.CPU.LoadCritical = 4.0
	}
	if cfg.Diagnostics.CPU.TemperatureWarning == 0 {
		cfg.Diagnostics.CPU.TemperatureWarning = 70
	}
	if cfg.Diagnostics.CPU.TemperatureCritical == 0 {
		cfg.Diagnostics.CPU.TemperatureCritical = 80
	}
	if cfg.Diagnostics.Memory.AvailableWarningPercent == 0 {
		cfg.Diagnostics.Memory.AvailableWarningPercent = 15
	}
	if cfg.Diagnostics.Memory.AvailableCriticalPercent == 0 {
		cfg.Diagnostics.Memory.AvailableCriticalPercent = 5
	}
	if cfg.Diagnostics.Memory.SwapWarning == 0 {
		cfg.Diagnostics.Memory.SwapWarning = 50
	}
	if cfg.Diagnostics.Disk.UsageWarning == 0 {
		cfg.Diagnostics.Disk.UsageWarning = 80
	}
	if cfg.Diagnostics.Disk.UsageCritical == 0 {
		cfg.Diagnostics.Disk.UsageCritical = 90
	}
	if cfg.Diagnostics.Disk.InodeWarning == 0 {
		cfg.Diagnostics.Disk.InodeWarning = 80
	}
	if cfg.Diagnostics.Disk.InodeCritical == 0 {
		cfg.Diagnostics.Disk.InodeCritical = 90
	}
	if cfg.Diagnostics.Network.LatencyWarning.Std() == 0 {
		cfg.Diagnostics.Network.LatencyWarning = Duration(100 * time.Millisecond)
	}
	if cfg.Diagnostics.Time.DriftWarning.Std() == 0 {
		cfg.Diagnostics.Time.DriftWarning = Duration(time.Second)
	}
	cfg.applyAlertDefaults()
}

func (cfg *Config) applyAlertDefaults() {
	if cfg.Alerts.Interval.Std() == 0 {
		cfg.Alerts.Interval = Duration(30 * time.Second)
	}
	if cfg.Alerts.Cooldown.Std() == 0 {
		cfg.Alerts.Cooldown = Duration(5 * time.Minute)
	}
	if cfg.Alerts.PersistenceThreshold.Std() == 0 {
		cfg.Alerts.PersistenceThreshold = Duration(30 * time.Second)
	}
	if cfg.Alerts.Retention.Std() == 0 {
		cfg.Alerts.Retention = Duration(30 * 24 * time.Hour)
	}
	defaultAlertCheck(&cfg.Alerts.Checks.Services, cfg.Alerts.Interval.Std())
	defaultAlertCheck(&cfg.Alerts.Checks.Containers, cfg.Alerts.Interval.Std())
	defaultAlertCheck(&cfg.Alerts.Checks.SQLite, time.Minute)
	defaultAlertCheck(&cfg.Alerts.Checks.Executor, cfg.Alerts.Interval.Std())
	if cfg.Alerts.Checks.Disk.Interval.Std() == 0 {
		cfg.Alerts.Checks.Disk.Interval = Duration(time.Minute)
	}
	if cfg.Alerts.Checks.Disk.Warning == 0 {
		cfg.Alerts.Checks.Disk.Warning = cfg.Diagnostics.Disk.UsageWarning
	}
	if cfg.Alerts.Checks.Disk.Critical == 0 {
		cfg.Alerts.Checks.Disk.Critical = cfg.Diagnostics.Disk.UsageCritical
	}
	if cfg.Alerts.Checks.Memory.Interval.Std() == 0 {
		cfg.Alerts.Checks.Memory.Interval = Duration(time.Minute)
	}
	if cfg.Alerts.Checks.Memory.PressureWarning == 0 {
		cfg.Alerts.Checks.Memory.PressureWarning = 0.5
	}
	if cfg.Alerts.Checks.Memory.PressureCritical == 0 {
		cfg.Alerts.Checks.Memory.PressureCritical = 0.8
	}
	if cfg.Alerts.Checks.CPU.Interval.Std() == 0 {
		cfg.Alerts.Checks.CPU.Interval = Duration(time.Minute)
	}
	if cfg.Alerts.Checks.CPU.LoadWarning == 0 {
		cfg.Alerts.Checks.CPU.LoadWarning = cfg.Diagnostics.CPU.LoadWarning
	}
	if cfg.Alerts.Checks.CPU.LoadCritical == 0 {
		cfg.Alerts.Checks.CPU.LoadCritical = cfg.Diagnostics.CPU.LoadCritical
	}
	if cfg.Alerts.Checks.CPU.TemperatureWarning == 0 {
		cfg.Alerts.Checks.CPU.TemperatureWarning = cfg.Diagnostics.CPU.TemperatureWarning
	}
	if cfg.Alerts.Checks.CPU.TemperatureCritical == 0 {
		cfg.Alerts.Checks.CPU.TemperatureCritical = cfg.Diagnostics.CPU.TemperatureCritical
	}
	if cfg.Alerts.Checks.AppErrors.Interval.Std() == 0 {
		cfg.Alerts.Checks.AppErrors.Interval = Duration(time.Minute)
	}
	if cfg.Alerts.Checks.AppErrors.Pattern == "" {
		cfg.Alerts.Checks.AppErrors.Pattern = "ERROR|FATAL"
	}
	if cfg.Alerts.Checks.AppErrors.Threshold == 0 {
		cfg.Alerts.Checks.AppErrors.Threshold = 5
	}
	if cfg.Alerts.Checks.Certificates.Interval.Std() == 0 {
		cfg.Alerts.Checks.Certificates.Interval = Duration(time.Hour)
	}
	if cfg.Alerts.Checks.Certificates.WarningDays == 0 {
		cfg.Alerts.Checks.Certificates.WarningDays = 30
	}
	if cfg.Alerts.Checks.Certificates.CriticalDays == 0 {
		cfg.Alerts.Checks.Certificates.CriticalDays = 7
	}
	if cfg.Alerts.Checks.Backups.Interval.Std() == 0 {
		cfg.Alerts.Checks.Backups.Interval = Duration(time.Hour)
	}
	if cfg.Alerts.Checks.Backups.MaxAge.Std() == 0 {
		cfg.Alerts.Checks.Backups.MaxAge = Duration(24 * time.Hour)
	}
}

func defaultAlertCheck(check *AlertCheckConfig, interval time.Duration) {
	if check.Interval.Std() == 0 {
		check.Interval = Duration(interval)
	}
}

func Validate(cfg Config) error {
	cfg.ApplyDefaults()
	var errs []error
	if strings.TrimSpace(cfg.Server.Name) == "" {
		errs = append(errs, errors.New("server.name is required"))
	}
	if strings.TrimSpace(cfg.Identity.AdministratorID) == "" {
		errs = append(errs, errors.New("identity.administrator_id is required"))
	}
	if !filepath.IsAbs(cfg.Database.Path) {
		errs = append(errs, errors.New("database.path must be absolute"))
	}
	if !filepath.IsAbs(cfg.Socket.Path) {
		errs = append(errs, errors.New("socket.path must be absolute"))
	}
	if !strings.HasPrefix(cfg.Socket.Path, "/run/") && !strings.HasPrefix(cfg.Socket.Path, "/var/run/") && !strings.HasPrefix(cfg.Socket.Path, os.TempDir()) {
		errs = append(errs, errors.New("socket.path must be under /run, /var/run, or the system temporary directory"))
	}
	if _, err := strconv.ParseUint(cfg.Socket.Mode, 8, 32); err != nil {
		errs = append(errs, errors.New("socket.mode must be an octal string"))
	}
	if cfg.Policies.Default != "deny" {
		errs = append(errs, errors.New("policies.default must be deny"))
	}
	if cfg.Policies.DestructiveActions != "deny" {
		errs = append(errs, errors.New("policies.destructive_actions must be deny"))
	}
	if cfg.Policies.ApprovalExpiration.Std() <= 0 {
		errs = append(errs, errors.New("policies.approval_expiration must be positive"))
	}
	if cfg.Limits.OperationTimeout.Std() <= 0 {
		errs = append(errs, errors.New("limits.operation_timeout must be positive"))
	}
	if cfg.Limits.MaxLogLines <= 0 || cfg.Limits.MaxLogLines > 200 {
		errs = append(errs, errors.New("limits.max_log_lines must be between 1 and 200"))
	}
	if cfg.Limits.MaxToolOutputBytes <= 0 || cfg.Limits.MaxToolOutputBytes > 1_048_576 {
		errs = append(errs, errors.New("limits.max_tool_output_bytes must be between 1 and 1048576"))
	}
	if cfg.Limits.MaxHealthcheckAttempts <= 0 || cfg.Limits.MaxHealthcheckAttempts > 10 {
		errs = append(errs, errors.New("limits.max_healthcheck_attempts must be between 1 and 10"))
	}
	for alias, diskPath := range cfg.Filesystem.DiskPaths {
		if !validAlias(alias) {
			errs = append(errs, fmt.Errorf("filesystem.disk_paths[%q] has an invalid alias", alias))
		}
		if !filepath.IsAbs(diskPath.Path) {
			errs = append(errs, fmt.Errorf("filesystem.disk_paths[%q].path must be absolute", alias))
		}
	}
	validateDiagnostics(&errs, cfg)
	validateAlerts(&errs, cfg)
	for alias := range cfg.Services {
		if _, ok := cfg.Containers[alias]; ok {
			errs = append(errs, fmt.Errorf("alias %q is ambiguous between services and containers", alias))
		}
	}
	for alias, svc := range cfg.Services {
		if !validAlias(alias) {
			errs = append(errs, fmt.Errorf("services[%q] has an invalid alias", alias))
		}
		if !validUnit(svc.Unit) {
			errs = append(errs, fmt.Errorf("services[%q].unit is invalid", alias))
		}
		validatePermission(&errs, alias, "status", svc.Permissions.Status, false)
		validatePermission(&errs, alias, "logs", svc.Permissions.Logs, false)
		validatePermission(&errs, alias, "restart", svc.Permissions.Restart, true)
		if svc.Healthcheck != nil {
			validateHealthcheck(&errs, alias, *svc.Healthcheck, cfg.Limits.MaxHealthcheckAttempts)
		}
	}
	validateTelegram(&errs, cfg)
	validatePodman(&errs, cfg)
	return errors.Join(errs...)
}

func validateAlerts(errs *[]error, cfg Config) {
	if !cfg.Alerts.Enabled {
		return
	}
	if cfg.Alerts.Interval.Std() <= 0 {
		*errs = append(*errs, errors.New("alerts.interval must be positive"))
	}
	if cfg.Alerts.Cooldown.Std() < 0 {
		*errs = append(*errs, errors.New("alerts.cooldown must not be negative"))
	}
	if cfg.Alerts.PersistenceThreshold.Std() < 0 {
		*errs = append(*errs, errors.New("alerts.persistence_threshold must not be negative"))
	}
	if cfg.Alerts.Retention.Std() <= 0 {
		*errs = append(*errs, errors.New("alerts.retention must be positive"))
	}
	validateAlertCheckInterval(errs, "alerts.checks.services.interval", cfg.Alerts.Checks.Services.Interval)
	validateAlertCheckInterval(errs, "alerts.checks.containers.interval", cfg.Alerts.Checks.Containers.Interval)
	validateAlertCheckInterval(errs, "alerts.checks.disk.interval", cfg.Alerts.Checks.Disk.Interval)
	validateAlertCheckInterval(errs, "alerts.checks.memory.interval", cfg.Alerts.Checks.Memory.Interval)
	validateAlertCheckInterval(errs, "alerts.checks.cpu.interval", cfg.Alerts.Checks.CPU.Interval)
	validateAlertCheckInterval(errs, "alerts.checks.sqlite.interval", cfg.Alerts.Checks.SQLite.Interval)
	validateAlertCheckInterval(errs, "alerts.checks.executor.interval", cfg.Alerts.Checks.Executor.Interval)
	validateIncreasingThreshold(errs, "alerts.checks.disk", cfg.Alerts.Checks.Disk.Warning, cfg.Alerts.Checks.Disk.Critical)
	validateIncreasingThreshold(errs, "alerts.checks.memory.pressure", cfg.Alerts.Checks.Memory.PressureWarning, cfg.Alerts.Checks.Memory.PressureCritical)
	validateIncreasingThreshold(errs, "alerts.checks.cpu.load", cfg.Alerts.Checks.CPU.LoadWarning, cfg.Alerts.Checks.CPU.LoadCritical)
	validateIncreasingThreshold(errs, "alerts.checks.cpu.temperature", cfg.Alerts.Checks.CPU.TemperatureWarning, cfg.Alerts.Checks.CPU.TemperatureCritical)
	if cfg.Alerts.Telegram.Enabled {
		if !cfg.Telegram.Enabled {
			*errs = append(*errs, errors.New("telegram.enabled must be true when alerts.telegram.enabled is true"))
		}
		if cfg.Alerts.Telegram.ChatID == 0 {
			*errs = append(*errs, errors.New("alerts.telegram.chat_id is required when alerts.telegram.enabled is true"))
		}
	}
	for _, window := range cfg.Alerts.SilenceSchedule {
		if !validClockHHMM(window.Start) || !validClockHHMM(window.End) {
			*errs = append(*errs, errors.New("alerts.silence_schedule start and end must use HH:MM"))
		}
		if window.Timezone != "" {
			if _, err := time.LoadLocation(window.Timezone); err != nil {
				*errs = append(*errs, fmt.Errorf("alerts.silence_schedule timezone %q is invalid", window.Timezone))
			}
		}
	}
}

func validateAlertCheckInterval(errs *[]error, name string, d Duration) {
	if d.Std() <= 0 {
		*errs = append(*errs, fmt.Errorf("%s must be positive", name))
	}
}

func validClockHHMM(value string) bool {
	_, err := time.Parse("15:04", value)
	return err == nil
}

func validateDiagnostics(errs *[]error, cfg Config) {
	validateIncreasingThreshold(errs, "diagnostics.cpu.load", cfg.Diagnostics.CPU.LoadWarning, cfg.Diagnostics.CPU.LoadCritical)
	validateIncreasingThreshold(errs, "diagnostics.cpu.temperature", cfg.Diagnostics.CPU.TemperatureWarning, cfg.Diagnostics.CPU.TemperatureCritical)
	validateIncreasingThreshold(errs, "diagnostics.memory.available", cfg.Diagnostics.Memory.AvailableCriticalPercent, cfg.Diagnostics.Memory.AvailableWarningPercent)
	validateIncreasingThreshold(errs, "diagnostics.disk.usage", cfg.Diagnostics.Disk.UsageWarning, cfg.Diagnostics.Disk.UsageCritical)
	validateIncreasingThreshold(errs, "diagnostics.disk.inode", cfg.Diagnostics.Disk.InodeWarning, cfg.Diagnostics.Disk.InodeCritical)
	for _, target := range cfg.Diagnostics.Network.PingTargets {
		if strings.TrimSpace(target) == "" || strings.ContainsAny(target, " \t\r\n") {
			*errs = append(*errs, fmt.Errorf("diagnostics.network.ping_targets contains an invalid target"))
		}
	}
	if cfg.Diagnostics.Network.LatencyWarning.Std() < 0 {
		*errs = append(*errs, errors.New("diagnostics.network.latency_warning must not be negative"))
	}
	if cfg.Diagnostics.Time.DriftWarning.Std() < 0 {
		*errs = append(*errs, errors.New("diagnostics.time.drift_warning must not be negative"))
	}
}

func validateIncreasingThreshold(errs *[]error, name string, warning, critical float64) {
	if warning <= 0 || critical <= 0 {
		*errs = append(*errs, fmt.Errorf("%s thresholds must be positive", name))
		return
	}
	if warning > critical {
		*errs = append(*errs, fmt.Errorf("%s warning threshold must not exceed critical threshold", name))
	}
}

func (cfg Config) TelegramToken() string {
	if strings.TrimSpace(cfg.Telegram.Token) != "" {
		return strings.TrimSpace(cfg.Telegram.Token)
	}
	envName := strings.TrimSpace(cfg.Telegram.TokenEnv)
	if envName == "" {
		envName = "SAFEOPS_TELEGRAM_TOKEN"
	}
	return strings.TrimSpace(os.Getenv(envName))
}

func (cfg Config) TelegramPrincipal() string {
	if cfg.Telegram.AdminID <= 0 {
		return ""
	}
	return fmt.Sprintf("telegram:%d", cfg.Telegram.AdminID)
}

func (cfg Config) ConfirmationCodeLength() int {
	if cfg.Telegram.Enabled && cfg.Telegram.Confirmation.CodeLength > 0 {
		return cfg.Telegram.Confirmation.CodeLength
	}
	return 4
}

func (cfg Config) ApprovalExpiration() time.Duration {
	if cfg.Telegram.Enabled && cfg.Telegram.Confirmation.ExpirationSeconds > 0 {
		return time.Duration(cfg.Telegram.Confirmation.ExpirationSeconds) * time.Second
	}
	return cfg.Policies.ApprovalExpiration.Std()
}

func validAlias(alias string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`).MatchString(alias)
}

func validUnit(unit string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]*\.service$`).MatchString(unit)
}

func validContainerName(name string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`).MatchString(name)
}

func validatePermission(errs *[]error, alias, name, value string, restart bool) {
	switch value {
	case "allow", "deny":
		if restart && value == "allow" {
			*errs = append(*errs, fmt.Errorf("services[%q].permissions.restart must be confirm or deny", alias))
		}
	case "confirm":
		if !restart {
			*errs = append(*errs, fmt.Errorf("services[%q].permissions.%s cannot be confirm", alias, name))
		}
	default:
		*errs = append(*errs, fmt.Errorf("services[%q].permissions.%s is unknown", alias, name))
	}
}

func validatePodman(errs *[]error, cfg Config) {
	if !cfg.Podman.Enabled {
		if len(cfg.Containers) > 0 || cfg.Podman.Binary != "" || cfg.Podman.Mode != "" || cfg.Podman.SystemdScope != "" {
			*errs = append(*errs, errors.New("podman configuration is present while podman.enabled is false"))
		}
		return
	}
	if !filepath.IsAbs(cfg.Podman.Binary) {
		*errs = append(*errs, errors.New("podman.binary must be absolute when podman is enabled"))
	} else if st, err := os.Stat(cfg.Podman.Binary); err != nil {
		*errs = append(*errs, fmt.Errorf("podman.binary must exist when podman is enabled: %w", err))
	} else if st.IsDir() {
		*errs = append(*errs, errors.New("podman.binary must be a file when podman is enabled"))
	}
	switch cfg.Podman.Mode {
	case "rootless", "system":
	default:
		*errs = append(*errs, errors.New("podman.mode must be rootless or system"))
	}
	switch cfg.Podman.SystemdScope {
	case "", "user", "system":
	default:
		*errs = append(*errs, errors.New("podman.systemd_scope must be user or system"))
	}
	for alias, ctr := range cfg.Containers {
		if !validAlias(alias) {
			*errs = append(*errs, fmt.Errorf("containers[%q] has an invalid alias", alias))
		}
		if !validContainerName(ctr.ContainerName) {
			*errs = append(*errs, fmt.Errorf("containers[%q].container_name is invalid", alias))
		}
		switch ctr.Management {
		case "podman":
		case "quadlet":
			if !validUnit(ctr.QuadletUnit) {
				*errs = append(*errs, fmt.Errorf("containers[%q].quadlet_unit is invalid", alias))
			}
		default:
			*errs = append(*errs, fmt.Errorf("containers[%q].management is unknown", alias))
		}
		validateContainerPermission(errs, alias, "status", ctr.Permissions.Status, false)
		validateContainerPermission(errs, alias, "logs", ctr.Permissions.Logs, false)
		validateContainerPermission(errs, alias, "restart", ctr.Permissions.Restart, true)
		maxLines := ctr.Logs.MaxLines
		if maxLines == 0 {
			maxLines = cfg.Limits.MaxLogLines
		}
		if maxLines <= 0 || maxLines > cfg.Limits.MaxLogLines {
			*errs = append(*errs, fmt.Errorf("containers[%q].logs.max_lines must be between 1 and limits.max_log_lines", alias))
		}
		attempts := ctr.Health.Attempts
		if attempts == 0 {
			attempts = cfg.Limits.MaxHealthcheckAttempts
		}
		if attempts <= 0 || attempts > cfg.Limits.MaxHealthcheckAttempts {
			*errs = append(*errs, fmt.Errorf("containers[%q].health.attempts is outside configured limits", alias))
		}
		if ctr.Health.Interval.Std() < 0 {
			*errs = append(*errs, fmt.Errorf("containers[%q].health.interval must be positive", alias))
		}
		if ctr.Permissions.Status == "deny" && ctr.Permissions.Logs == "deny" && ctr.Permissions.Restart == "deny" {
			*errs = append(*errs, fmt.Errorf("containers[%q] denies all operations without a documented reason", alias))
		}
	}
}

func validateTelegram(errs *[]error, cfg Config) {
	if !cfg.Telegram.Enabled {
		return
	}
	if cfg.Telegram.Token != "" {
		*errs = append(*errs, errors.New("telegram.token must not be set in the shared configuration; use telegram.token_env or SAFEOPS_TELEGRAM_TOKEN"))
	}
	tokenEnv := strings.TrimSpace(cfg.Telegram.TokenEnv)
	if tokenEnv == "" {
		tokenEnv = "SAFEOPS_TELEGRAM_TOKEN"
	}
	if !validEnvName(tokenEnv) {
		*errs = append(*errs, errors.New("telegram.token_env must be a valid environment variable name"))
	}
	if strings.TrimSpace(os.Getenv(tokenEnv)) == "" {
		*errs = append(*errs, fmt.Errorf("%s must contain the Telegram bot token when telegram is enabled", tokenEnv))
	}
	if cfg.Telegram.AdminID <= 0 {
		*errs = append(*errs, errors.New("telegram.admin_id must be positive"))
	}
	allowed := map[int64]bool{}
	for _, id := range cfg.Telegram.AllowedUsers {
		if id <= 0 {
			*errs = append(*errs, errors.New("telegram.allowed_users must contain only positive numeric IDs"))
			continue
		}
		if allowed[id] {
			*errs = append(*errs, fmt.Errorf("telegram.allowed_users contains duplicate ID %d", id))
		}
		allowed[id] = true
	}
	if len(allowed) == 0 {
		*errs = append(*errs, errors.New("telegram.allowed_users must not be empty when telegram is enabled"))
	}
	if cfg.Telegram.AdminID > 0 && !allowed[cfg.Telegram.AdminID] {
		*errs = append(*errs, errors.New("telegram.admin_id must be listed in telegram.allowed_users"))
	}
	if cfg.Telegram.AdminID > 0 && cfg.Identity.AdministratorID != cfg.TelegramPrincipal() {
		*errs = append(*errs, fmt.Errorf("identity.administrator_id must be %q when telegram is enabled", cfg.TelegramPrincipal()))
	}
	if cfg.Telegram.RateLimit.MessagesPerMinute <= 0 || cfg.Telegram.RateLimit.MessagesPerMinute > 60 {
		*errs = append(*errs, errors.New("telegram.rate_limit.messages_per_minute must be between 1 and 60"))
	}
	if cfg.Telegram.MessageSizeLimit <= 0 || cfg.Telegram.MessageSizeLimit > 4096 {
		*errs = append(*errs, errors.New("telegram.message_size_limit must be between 1 and 4096"))
	}
	if cfg.Telegram.Confirmation.CodeLength < 4 || cfg.Telegram.Confirmation.CodeLength > 12 {
		*errs = append(*errs, errors.New("telegram.confirmation.code_length must be between 4 and 12"))
	}
	if cfg.Telegram.Confirmation.ExpirationSeconds <= 0 || cfg.Telegram.Confirmation.ExpirationSeconds > 3600 {
		*errs = append(*errs, errors.New("telegram.confirmation.expiration_seconds must be between 1 and 3600"))
	}
	if strings.TrimSpace(cfg.Telegram.OpenClaw.Command) == "" {
		*errs = append(*errs, errors.New("telegram.openclaw.command is required when telegram is enabled"))
	}
	if cfg.Telegram.OpenClaw.Timeout.Std() <= 0 {
		*errs = append(*errs, errors.New("telegram.openclaw.timeout must be positive"))
	}
}

func validEnvName(name string) bool {
	return regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`).MatchString(name)
}

func validateContainerPermission(errs *[]error, alias, name, value string, restart bool) {
	switch value {
	case "allow", "deny":
		if restart && value == "allow" {
			*errs = append(*errs, fmt.Errorf("containers[%q].permissions.restart must be confirm or deny", alias))
		}
	case "confirm":
		if !restart {
			*errs = append(*errs, fmt.Errorf("containers[%q].permissions.%s cannot be confirm", alias, name))
		}
	default:
		*errs = append(*errs, fmt.Errorf("containers[%q].permissions.%s is unknown", alias, name))
	}
}

func validateHealthcheck(errs *[]error, alias string, hc HealthcheckConfig, maxAttempts int) {
	parsed, err := url.Parse(hc.URL)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" {
		*errs = append(*errs, fmt.Errorf("services[%q].healthcheck.url must be an http://127.0.0.1 URL", alias))
	}
	if hc.Timeout.Std() <= 0 {
		*errs = append(*errs, fmt.Errorf("services[%q].healthcheck.timeout must be positive", alias))
	}
	if hc.Attempts <= 0 || hc.Attempts > maxAttempts {
		*errs = append(*errs, fmt.Errorf("services[%q].healthcheck.attempts is outside configured limits", alias))
	}
	if hc.Interval.Std() <= 0 {
		*errs = append(*errs, fmt.Errorf("services[%q].healthcheck.interval must be positive", alias))
	}
}
