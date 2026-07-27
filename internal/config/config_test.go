package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateAcceptsExampleShape(t *testing.T) {
	cfg := validConfig()
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsInvalidUnit(t *testing.T) {
	cfg := validConfig()
	svc := cfg.Services["service-alpha"]
	svc.Unit = "bad unit"
	cfg.Services["service-alpha"] = svc
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate() error = nil, want error")
	}
}

func TestValidateRejectsRestartAllow(t *testing.T) {
	cfg := validConfig()
	svc := cfg.Services["service-alpha"]
	svc.Permissions.Restart = "allow"
	cfg.Services["service-alpha"] = svc
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate() error = nil, want error")
	}
}

func TestValidateRejectsFreeSocketPath(t *testing.T) {
	cfg := validConfig()
	cfg.Socket.Path = "/home/operator/safeops.sock"
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate() error = nil, want error")
	}
}

func TestLoadParsesDurationsAndKnownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := strings.ReplaceAll(exampleYAML(), "/tmp/safeops-test.db", filepath.Join(dir, "safeops.db"))
	data = strings.ReplaceAll(data, "/tmp/safeops.sock", filepath.Join(dir, "safeops.sock"))
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policies.ApprovalExpiration.Std() != 5*time.Minute {
		t.Fatalf("approval expiration = %s", cfg.Policies.ApprovalExpiration.Std())
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(exampleYAML()+"unknown: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() error = nil, want unknown field error")
	}
}

func TestValidateHealthcheckRules(t *testing.T) {
	cfg := validConfig()
	svc := cfg.Services["service-alpha"]
	svc.Healthcheck = &HealthcheckConfig{URL: "http://127.0.0.1:8080/health", Timeout: Duration(time.Second), Attempts: 1, Interval: Duration(time.Second)}
	cfg.Services["service-alpha"] = svc
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	svc.Healthcheck.URL = "http://example.com/health"
	cfg.Services["service-alpha"] = svc
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate() error = nil, want healthcheck URL error")
	}
}

func TestValidateRejectsInvalidPolicyAndLimits(t *testing.T) {
	cfg := validConfig()
	cfg.Server.Name = ""
	cfg.Identity.AdministratorID = ""
	cfg.Database.Path = "relative.db"
	cfg.Socket.Path = "relative.sock"
	cfg.Socket.Mode = "not-octal"
	cfg.Policies.Default = "allow"
	cfg.Policies.DestructiveActions = "allow"
	cfg.Policies.ApprovalExpiration = 0
	cfg.Limits.OperationTimeout = 0
	cfg.Limits.MaxLogLines = 201
	cfg.Limits.MaxToolOutputBytes = 0
	cfg.Limits.MaxHealthcheckAttempts = 11
	cfg.Filesystem.DiskPaths["bad alias"] = DiskPathConfig{Path: "relative"}
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate() error = nil, want multiple errors")
	}
}

func TestValidateRejectsPermissionAndHealthcheckLimitErrors(t *testing.T) {
	cfg := validConfig()
	svc := cfg.Services["service-alpha"]
	svc.Permissions.Status = "confirm"
	svc.Permissions.Logs = "free"
	svc.Healthcheck = &HealthcheckConfig{URL: ":", Timeout: 0, Attempts: 99, Interval: 0}
	cfg.Services["service-alpha"] = svc
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate() error = nil, want permission and healthcheck errors")
	}
}

func TestValidatePodmanConfiguration(t *testing.T) {
	cfg := validConfig()
	cfg.Podman = PodmanConfig{Enabled: true, Binary: "/usr/bin/podman", Mode: "rootless", SystemdScope: "user"}
	cfg.Containers = map[string]ContainerConfig{
		"container-alpha": {
			ContainerName: "app-alpha-container",
			Management:    "podman",
			Permissions:   PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
			Logs:          ContainerLogsConfig{MaxLines: 100},
			Health:        ContainerHealthConfig{RequireHealthyAfterRestart: true, Attempts: 3, Interval: Duration(time.Second)},
		},
		"workload-alpha": {
			ContainerName: "worker-alpha-container",
			Management:    "quadlet",
			QuadletUnit:   "worker-alpha.service",
			Permissions:   PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
		},
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsInvalidPodmanConfiguration(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"disabled with containers", func(cfg *Config) {
			cfg.Containers = map[string]ContainerConfig{"container-alpha": {ContainerName: "app-alpha-container", Management: "podman"}}
		}},
		{"relative binary", func(cfg *Config) {
			enablePodmanForTest(cfg)
			cfg.Podman.Binary = "podman"
		}},
		{"unknown mode", func(cfg *Config) {
			enablePodmanForTest(cfg)
			cfg.Podman.Mode = "free"
		}},
		{"ambiguous alias", func(cfg *Config) {
			enablePodmanForTest(cfg)
			cfg.Containers["service-alpha"] = cfg.Containers["container-alpha"]
		}},
		{"container starts with dash", func(cfg *Config) {
			enablePodmanForTest(cfg)
			item := cfg.Containers["container-alpha"]
			item.ContainerName = "-bad"
			cfg.Containers["container-alpha"] = item
		}},
		{"quadlet missing unit", func(cfg *Config) {
			enablePodmanForTest(cfg)
			item := cfg.Containers["container-alpha"]
			item.Management = "quadlet"
			item.QuadletUnit = ""
			cfg.Containers["container-alpha"] = item
		}},
		{"restart allow", func(cfg *Config) {
			enablePodmanForTest(cfg)
			item := cfg.Containers["container-alpha"]
			item.Permissions.Restart = "allow"
			cfg.Containers["container-alpha"] = item
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			if err := Validate(cfg); err == nil {
				t.Fatal("Validate() error = nil, want error")
			}
		})
	}
}

func enablePodmanForTest(cfg *Config) {
	cfg.Podman = PodmanConfig{Enabled: true, Binary: "/usr/bin/podman", Mode: "rootless", SystemdScope: "user"}
	cfg.Containers = map[string]ContainerConfig{
		"container-alpha": {
			ContainerName: "app-alpha-container",
			Management:    "podman",
			Permissions:   PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
			Logs:          ContainerLogsConfig{MaxLines: 100},
			Health:        ContainerHealthConfig{Attempts: 3, Interval: Duration(time.Second)},
		},
	}
}

func validConfig() Config {
	return Config{
		Server:   ServerConfig{Name: "host-alpha"},
		Identity: IdentityConfig{AdministratorID: "operator"},
		Database: DatabaseConfig{Path: "/var/lib/safeops/safeops.db"},
		Socket:   SocketConfig{Path: "/run/safeops/safeops.sock", Group: "safeops", Mode: "0660"},
		Policies: PoliciesConfig{Default: "deny", DestructiveActions: "deny", ApprovalExpiration: Duration(5 * 60 * 1_000_000_000)},
		Limits:   LimitsConfig{OperationTimeout: Duration(15 * 1_000_000_000), MaxLogLines: 200, MaxToolOutputBytes: 65536, MaxHealthcheckAttempts: 5},
		Filesystem: FilesystemConfig{DiskPaths: map[string]DiskPathConfig{
			"root": {Path: "/"},
		}},
		Services: map[string]ServiceConfig{
			"service-alpha": {
				Unit: "app-alpha.service",
				Permissions: PermissionsConfig{
					Status:  "allow",
					Logs:    "allow",
					Restart: "confirm",
				},
			},
		},
	}
}

func exampleYAML() string {
	return `server:
  name: host-alpha
identity:
  administrator_id: operator
database:
  path: /tmp/safeops-test.db
socket:
  path: /tmp/safeops.sock
  group: safeops
  mode: "0660"
policies:
  default: deny
  destructive_actions: deny
  approval_expiration: 5m
  dry_run: false
limits:
  operation_timeout: 15s
  max_log_lines: 200
  max_tool_output_bytes: 65536
  max_healthcheck_attempts: 5
filesystem:
  disk_paths:
    root:
      path: /
services:
  service-alpha:
    unit: app-alpha.service
    permissions:
      status: allow
      logs: allow
      restart: confirm
`
}
