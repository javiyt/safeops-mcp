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
	Server     ServerConfig               `yaml:"server"`
	Identity   IdentityConfig             `yaml:"identity"`
	Database   DatabaseConfig             `yaml:"database"`
	Socket     SocketConfig               `yaml:"socket"`
	Policies   PoliciesConfig             `yaml:"policies"`
	Limits     LimitsConfig               `yaml:"limits"`
	Filesystem FilesystemConfig           `yaml:"filesystem"`
	Services   map[string]ServiceConfig   `yaml:"services"`
	Podman     PodmanConfig               `yaml:"podman"`
	Containers map[string]ContainerConfig `yaml:"containers"`
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
	return cfg, Validate(cfg)
}

func Validate(cfg Config) error {
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
	validatePodman(&errs, cfg)
	return errors.Join(errs...)
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
