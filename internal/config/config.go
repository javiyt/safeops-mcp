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
	Server          ServerConfig                 `yaml:"server"`
	Identity        IdentityConfig               `yaml:"identity"`
	Database        DatabaseConfig               `yaml:"database"`
	Socket          SocketConfig                 `yaml:"socket"`
	Policies        PoliciesConfig               `yaml:"policies"`
	Limits          LimitsConfig                 `yaml:"limits"`
	Filesystem      FilesystemConfig             `yaml:"filesystem"`
	Diagnostics     DiagnosticsConfig            `yaml:"diagnostics"`
	Alerts          AlertsConfig                 `yaml:"alerts"`
	Telegram        TelegramConfig               `yaml:"telegram"`
	Services        map[string]ServiceConfig     `yaml:"services"`
	Podman          PodmanConfig                 `yaml:"podman"`
	Containers      map[string]ContainerConfig   `yaml:"containers"`
	Groups          map[string]GroupConfig       `yaml:"groups"`
	Applications    map[string]ApplicationConfig `yaml:"applications"`
	LogRotation     LogRotationConfig            `yaml:"log_rotation"`
	CacheCleanup    CacheCleanupConfig           `yaml:"cache_cleanup"`
	AuditRetention  Duration                     `yaml:"audit_retention"`
	AuditMinRecords int                          `yaml:"audit_min_records"`
	HostReboot      HostRebootConfig             `yaml:"host_reboot"`
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
	Unit        string                    `yaml:"unit"`
	Permissions PermissionsConfig         `yaml:"permissions"`
	Healthcheck *HealthcheckConfig        `yaml:"healthcheck,omitempty"`
	LogPath     string                    `yaml:"log_path"`
	LogRotation ResourceLogRotationConfig `yaml:"log_rotation"`
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
	ContainerName string                    `yaml:"container_name"`
	Management    string                    `yaml:"management"`
	QuadletUnit   string                    `yaml:"quadlet_unit"`
	Permissions   PermissionsConfig         `yaml:"permissions"`
	Logs          ContainerLogsConfig       `yaml:"logs"`
	Health        ContainerHealthConfig     `yaml:"health"`
	LogPath       string                    `yaml:"log_path"`
	LogRotation   ResourceLogRotationConfig `yaml:"log_rotation"`
}

type GroupConfig struct {
	Resources   []string `yaml:"resources"`
	Order       []string `yaml:"order"`
	StopOrder   []string `yaml:"stop_order"`
	Timeout     Duration `yaml:"timeout"`
	HealthCheck bool     `yaml:"health_check"`
}

type ResourceLogRotationConfig struct {
	Enabled  bool     `yaml:"enabled"`
	MaxSize  ByteSize `yaml:"max_size"`
	MaxAge   Duration `yaml:"max_age"`
	Compress bool     `yaml:"compress"`
	Keep     int      `yaml:"keep"`
}

type LogRotationConfig struct {
	Default      ResourceLogRotationConfig `yaml:"default"`
	MaxTotalSize ByteSize                  `yaml:"max_total_size"`
}

type ApplicationConfig struct {
	CachePath string                `yaml:"cache_path"`
	Cleanup   ResourceCleanupConfig `yaml:"cleanup"`
}

type ResourceCleanupConfig struct {
	Enabled bool     `yaml:"enabled"`
	MaxAge  Duration `yaml:"max_age"`
	MaxSize ByteSize `yaml:"max_size"`
	Timeout Duration `yaml:"timeout"`
}

type CacheCleanupConfig struct {
	Default ResourceCleanupConfig `yaml:"default"`
}

type HostRebootConfig struct {
	Enabled                bool     `yaml:"enabled"`
	AllowedUsers           []string `yaml:"allowed_users"`
	ConfirmationCodeLength int      `yaml:"confirmation_code_length"`
	ConfirmationWindow     Duration `yaml:"confirmation_window"`
	RequireBackup          bool     `yaml:"require_backup"`
	RebootCommand          string   `yaml:"reboot_command"`
	CancelCommand          string   `yaml:"cancel_command"`
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
	parsed, err := parseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

type ByteSize int64

func (s *ByteSize) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		return err
	}
	parsed, err := parseByteSize(raw)
	if err != nil {
		return fmt.Errorf("invalid byte size %q: %w", raw, err)
	}
	*s = ByteSize(parsed)
	return nil
}

func (s ByteSize) Int64() int64 {
	return int64(s)
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
	cfg.applyMaintenanceDefaults()
}

func (cfg *Config) applyMaintenanceDefaults() {
	if cfg.LogRotation.Default.MaxSize.Int64() == 0 {
		cfg.LogRotation.Default.MaxSize = ByteSize(100 * 1024 * 1024)
	}
	if cfg.LogRotation.Default.MaxAge.Std() == 0 {
		cfg.LogRotation.Default.MaxAge = Duration(7 * 24 * time.Hour)
	}
	if cfg.LogRotation.Default.Keep == 0 {
		cfg.LogRotation.Default.Keep = 5
	}
	if cfg.LogRotation.MaxTotalSize.Int64() == 0 {
		cfg.LogRotation.MaxTotalSize = ByteSize(1024 * 1024 * 1024)
	}
	if cfg.CacheCleanup.Default.MaxAge.Std() == 0 {
		cfg.CacheCleanup.Default.MaxAge = Duration(24 * time.Hour)
	}
	if cfg.CacheCleanup.Default.MaxSize.Int64() == 0 {
		cfg.CacheCleanup.Default.MaxSize = ByteSize(1024 * 1024 * 1024)
	}
	if cfg.CacheCleanup.Default.Timeout.Std() == 0 {
		cfg.CacheCleanup.Default.Timeout = Duration(30 * time.Second)
	}
	if cfg.AuditRetention.Std() == 0 {
		cfg.AuditRetention = Duration(90 * 24 * time.Hour)
	}
	if cfg.AuditMinRecords == 0 {
		cfg.AuditMinRecords = 1000
	}
	if cfg.HostReboot.ConfirmationCodeLength == 0 {
		cfg.HostReboot.ConfirmationCodeLength = 6
	}
	if cfg.HostReboot.ConfirmationWindow.Std() == 0 {
		cfg.HostReboot.ConfirmationWindow = Duration(5 * time.Minute)
	}
	if cfg.HostReboot.RebootCommand == "" {
		cfg.HostReboot.RebootCommand = "/usr/bin/sudo"
	}
	if cfg.HostReboot.CancelCommand == "" {
		cfg.HostReboot.CancelCommand = "/usr/bin/sudo"
	}
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
	validateMaintenance(&errs, cfg)
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
		validateLogConfig(&errs, "services["+alias+"]", svc.LogPath, svc.LogRotation, cfg.LogRotation.Default)
	}
	validateTelegram(&errs, cfg)
	validatePodman(&errs, cfg)
	return errors.Join(errs...)
}

func validateMaintenance(errs *[]error, cfg Config) {
	if cfg.LogRotation.Default.MaxSize.Int64() <= 0 {
		*errs = append(*errs, errors.New("log_rotation.default.max_size must be positive"))
	}
	if cfg.LogRotation.Default.MaxAge.Std() <= 0 {
		*errs = append(*errs, errors.New("log_rotation.default.max_age must be positive"))
	}
	if cfg.LogRotation.Default.Keep <= 0 || cfg.LogRotation.Default.Keep > 50 {
		*errs = append(*errs, errors.New("log_rotation.default.keep must be between 1 and 50"))
	}
	if cfg.LogRotation.MaxTotalSize.Int64() <= 0 {
		*errs = append(*errs, errors.New("log_rotation.max_total_size must be positive"))
	}
	if cfg.CacheCleanup.Default.MaxAge.Std() <= 0 {
		*errs = append(*errs, errors.New("cache_cleanup.default.max_age must be positive"))
	}
	if cfg.CacheCleanup.Default.MaxSize.Int64() <= 0 {
		*errs = append(*errs, errors.New("cache_cleanup.default.max_size must be positive"))
	}
	if cfg.CacheCleanup.Default.Timeout.Std() <= 0 {
		*errs = append(*errs, errors.New("cache_cleanup.default.timeout must be positive"))
	}
	if cfg.AuditRetention.Std() <= 0 {
		*errs = append(*errs, errors.New("audit_retention must be positive"))
	}
	if cfg.AuditMinRecords < 0 {
		*errs = append(*errs, errors.New("audit_min_records must not be negative"))
	}
	for alias, group := range cfg.Groups {
		if !validAlias(alias) {
			*errs = append(*errs, fmt.Errorf("groups[%q] has an invalid alias", alias))
		}
		if len(group.Resources) == 0 {
			*errs = append(*errs, fmt.Errorf("groups[%q].resources must not be empty", alias))
		}
		seen := map[string]bool{}
		for _, resource := range group.Resources {
			if !cfg.hasResource(resource) {
				*errs = append(*errs, fmt.Errorf("groups[%q].resources contains unknown resource %q", alias, resource))
			}
			if seen[resource] {
				*errs = append(*errs, fmt.Errorf("groups[%q].resources contains duplicate resource %q", alias, resource))
			}
			seen[resource] = true
		}
		validateGroupOrder(errs, alias, "order", group.Resources, group.Order)
		validateGroupOrder(errs, alias, "stop_order", group.Resources, group.StopOrder)
		if group.Timeout.Std() < 0 {
			*errs = append(*errs, fmt.Errorf("groups[%q].timeout must not be negative", alias))
		}
	}
	for alias, app := range cfg.Applications {
		if !validAlias(alias) {
			*errs = append(*errs, fmt.Errorf("applications[%q] has an invalid alias", alias))
		}
		if strings.TrimSpace(app.CachePath) == "" {
			*errs = append(*errs, fmt.Errorf("applications[%q].cache_path is required", alias))
		} else if !filepath.IsAbs(app.CachePath) {
			*errs = append(*errs, fmt.Errorf("applications[%q].cache_path must be absolute", alias))
		}
		cleanup := mergeCleanup(app.Cleanup, cfg.CacheCleanup.Default)
		if app.Cleanup.Enabled && (cleanup.MaxAge.Std() <= 0 || cleanup.MaxSize.Int64() <= 0 || cleanup.Timeout.Std() <= 0) {
			*errs = append(*errs, fmt.Errorf("applications[%q].cleanup limits must be positive", alias))
		}
	}
	if cfg.HostReboot.Enabled {
		if cfg.HostReboot.ConfirmationCodeLength < 6 || cfg.HostReboot.ConfirmationCodeLength > 12 {
			*errs = append(*errs, errors.New("host_reboot.confirmation_code_length must be between 6 and 12"))
		}
		if cfg.HostReboot.ConfirmationWindow.Std() <= 0 {
			*errs = append(*errs, errors.New("host_reboot.confirmation_window must be positive"))
		}
		if !filepath.IsAbs(cfg.HostReboot.RebootCommand) {
			*errs = append(*errs, errors.New("host_reboot.reboot_command must be absolute"))
		}
		if !filepath.IsAbs(cfg.HostReboot.CancelCommand) {
			*errs = append(*errs, errors.New("host_reboot.cancel_command must be absolute"))
		}
	}
}

func validateLogConfig(errs *[]error, name, path string, local, def ResourceLogRotationConfig) {
	if !local.Enabled {
		return
	}
	if strings.TrimSpace(path) == "" {
		*errs = append(*errs, fmt.Errorf("%s.log_path is required when log_rotation.enabled is true", name))
		return
	}
	if !filepath.IsAbs(path) {
		*errs = append(*errs, fmt.Errorf("%s.log_path must be absolute", name))
	}
	merged := mergeLogRotation(local, def)
	if merged.MaxSize.Int64() <= 0 || merged.MaxAge.Std() <= 0 || merged.Keep <= 0 || merged.Keep > 50 {
		*errs = append(*errs, fmt.Errorf("%s.log_rotation limits are invalid", name))
	}
}

func validateGroupOrder(errs *[]error, alias, field string, resources, order []string) {
	if len(order) == 0 {
		return
	}
	if len(order) != len(resources) {
		*errs = append(*errs, fmt.Errorf("groups[%q].%s must include every group resource exactly once", alias, field))
		return
	}
	allowed := map[string]int{}
	for _, resource := range resources {
		allowed[resource]++
	}
	for _, resource := range order {
		if allowed[resource] != 1 {
			*errs = append(*errs, fmt.Errorf("groups[%q].%s contains unknown or duplicate resource %q", alias, field, resource))
		}
		allowed[resource]--
	}
}

func (cfg Config) hasResource(alias string) bool {
	if _, ok := cfg.Services[alias]; ok {
		return true
	}
	if _, ok := cfg.Containers[alias]; ok {
		return true
	}
	return false
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
		validateLogConfig(errs, "containers["+alias+"]", ctr.LogPath, ctr.LogRotation, cfg.LogRotation.Default)
	}
}

func mergeLogRotation(local, def ResourceLogRotationConfig) ResourceLogRotationConfig {
	if local.MaxSize.Int64() == 0 {
		local.MaxSize = def.MaxSize
	}
	if local.MaxAge.Std() == 0 {
		local.MaxAge = def.MaxAge
	}
	if local.Keep == 0 {
		local.Keep = def.Keep
	}
	return local
}

func mergeCleanup(local, def ResourceCleanupConfig) ResourceCleanupConfig {
	if local.MaxAge.Std() == 0 {
		local.MaxAge = def.MaxAge
	}
	if local.MaxSize.Int64() == 0 {
		local.MaxSize = def.MaxSize
	}
	if local.Timeout.Std() == 0 {
		local.Timeout = def.Timeout
	}
	return local
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

func parseDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasSuffix(raw, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(raw, "d"))
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("day duration must be positive")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(raw)
}

func parseByteSize(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, errors.New("empty byte size")
	}
	multiplier := int64(1)
	upper := strings.ToUpper(raw)
	for _, unit := range []struct {
		suffix string
		value  int64
	}{
		{"GB", 1024 * 1024 * 1024},
		{"MB", 1024 * 1024},
		{"KB", 1024},
		{"B", 1},
	} {
		suffix, value := unit.suffix, unit.value
		if strings.HasSuffix(upper, suffix) {
			multiplier = value
			raw = strings.TrimSpace(raw[:len(raw)-len(suffix)])
			break
		}
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("byte size must be a positive integer with optional B, KB, MB, or GB suffix")
	}
	return value * multiplier, nil
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
