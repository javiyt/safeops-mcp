package executorhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/ports"
)

type Server struct {
	Config   config.Config
	Backend  ports.ExecutorServer
	Logger   *slog.Logger
	Listen   func(network, address string) (net.Listener, error)
	listener net.Listener
	server   *http.Server
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if err := os.RemoveAll(s.Config.Socket.Path); err != nil {
		return err
	}
	listen := s.Listen
	if listen == nil {
		listen = net.Listen
	}
	listener, err := listen("unix", s.Config.Socket.Path)
	if err != nil {
		return err
	}
	s.listener = listener
	mode, err := strconv.ParseUint(s.Config.Socket.Mode, 8, 32)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.Config.Socket.Path, os.FileMode(mode)); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/system/status", s.handleSystemStatus)
	mux.HandleFunc("GET /v1/disks/{alias}", s.handleDiskStatus)
	mux.HandleFunc("GET /v1/diagnostics/cpu", s.handleCPUStatus)
	mux.HandleFunc("GET /v1/diagnostics/memory", s.handleMemoryStatus)
	mux.HandleFunc("GET /v1/diagnostics/disks", s.handleDiskHealth)
	mux.HandleFunc("GET /v1/diagnostics/disks/{alias}", s.handleDiskHealth)
	mux.HandleFunc("GET /v1/diagnostics/network", s.handleNetworkStatus)
	mux.HandleFunc("GET /v1/diagnostics/time", s.handleTimeStatus)
	mux.HandleFunc("GET /v1/diagnostics/processes", s.handleConfiguredProcessStatus)
	mux.HandleFunc("GET /v1/diagnostics/health-summary", s.handleHostHealthSummary)
	mux.HandleFunc("GET /v1/services", s.handleListServices)
	mux.HandleFunc("GET /v1/services/{alias}/status", s.handleServiceStatus)
	mux.HandleFunc("POST /v1/services/logs", s.handleServiceLogs)
	mux.HandleFunc("POST /v1/services/restart", s.handleRestartService)
	mux.HandleFunc("GET /v1/containers", s.handleListContainers)
	mux.HandleFunc("GET /v1/containers/{alias}/status", s.handleContainerStatus)
	mux.HandleFunc("POST /v1/containers/logs", s.handleContainerLogs)
	mux.HandleFunc("POST /v1/containers/restart", s.handleRestartContainer)
	mux.HandleFunc("POST /v1/maintenance/groups/restart", s.handleRestartGroup)
	mux.HandleFunc("POST /v1/maintenance/logs/rotate", s.handleRotateLogs)
	mux.HandleFunc("POST /v1/maintenance/cache/cleanup", s.handleCleanupCache)
	mux.HandleFunc("POST /v1/maintenance/reset-failure", s.handleResetFailureState)
	mux.HandleFunc("POST /v1/maintenance/reboot", s.handleRebootHost)
	mux.HandleFunc("POST /v1/maintenance/reboot/cancel", s.handleCancelHostReboot)
	mux.HandleFunc("GET /v1/applications/{alias}/version", s.handleApplicationVersion)
	mux.HandleFunc("GET /v1/applications/{alias}/check-update", s.handleCheckApplicationUpdate)
	mux.HandleFunc("POST /v1/applications/update", s.handleUpdateApplication)
	mux.HandleFunc("POST /v1/applications/rollback", s.handleRollbackApplication)
	mux.HandleFunc("POST /v1/backups/create", s.handleCreateBackup)
	mux.HandleFunc("POST /v1/backups/verify", s.handleVerifyBackup)
	mux.HandleFunc("POST /v1/backups/retention", s.handleApplyRetentionPolicy)
	mux.HandleFunc("POST /v1/backups/restore-plan", s.handleGenerateRestorePlan)
	s.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
	}()
	err = s.server.Serve(listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.SystemStatus(r.Context())
	writeJSON(w, out, err)
}

func (s *Server) handleDiskStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.DiskStatus(r.Context(), r.PathValue("alias"))
	writeJSON(w, out, err)
}

func (s *Server) handleCPUStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.CPUStatus(r.Context())
	writeJSON(w, out, err)
}

func (s *Server) handleMemoryStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.MemoryStatus(r.Context())
	writeJSON(w, out, err)
}

func (s *Server) handleDiskHealth(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.DiskHealth(r.Context(), r.PathValue("alias"))
	writeJSON(w, out, err)
}

func (s *Server) handleNetworkStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.NetworkStatus(r.Context())
	writeJSON(w, out, err)
}

func (s *Server) handleTimeStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.TimeStatus(r.Context())
	writeJSON(w, out, err)
}

func (s *Server) handleConfiguredProcessStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.ConfiguredProcessStatus(r.Context())
	writeJSON(w, out, err)
}

func (s *Server) handleHostHealthSummary(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.HostHealthSummary(r.Context())
	writeJSON(w, out, err)
}

func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.ListServices(r.Context())
	writeJSON(w, map[string]any{"services": out}, err)
}

func (s *Server) handleServiceStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.ServiceStatus(r.Context(), r.PathValue("alias"))
	writeJSON(w, out, err)
}

func (s *Server) handleServiceLogs(w http.ResponseWriter, r *http.Request) {
	var req ports.ServiceLogsRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.ServiceLogs(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleRestartService(w http.ResponseWriter, r *http.Request) {
	var req ports.RestartServiceRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.RestartService(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleListContainers(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.ListContainers(r.Context())
	writeJSON(w, map[string]any{"containers": out}, err)
}

func (s *Server) handleContainerStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.ContainerStatus(r.Context(), r.PathValue("alias"))
	writeJSON(w, out, err)
}

func (s *Server) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	var req ports.ContainerLogsRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.ContainerLogs(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleRestartContainer(w http.ResponseWriter, r *http.Request) {
	var req ports.RestartContainerRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.RestartContainer(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleRestartGroup(w http.ResponseWriter, r *http.Request) {
	var req ports.RestartGroupRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.RestartGroup(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleRotateLogs(w http.ResponseWriter, r *http.Request) {
	var req ports.RotateLogsRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.RotateLogs(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleCleanupCache(w http.ResponseWriter, r *http.Request) {
	var req ports.CleanupCacheRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.CleanupCache(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleResetFailureState(w http.ResponseWriter, r *http.Request) {
	var req ports.ResetFailureStateRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.ResetFailureState(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleRebootHost(w http.ResponseWriter, r *http.Request) {
	var req ports.RebootHostRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.RebootHost(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleCancelHostReboot(w http.ResponseWriter, r *http.Request) {
	var req ports.RebootHostRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.CancelHostReboot(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleApplicationVersion(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.ApplicationVersion(r.Context(), ports.ApplicationVersionRequest{Application: r.PathValue("alias")})
	writeJSON(w, out, err)
}

func (s *Server) handleCheckApplicationUpdate(w http.ResponseWriter, r *http.Request) {
	out, err := s.Backend.CheckApplicationUpdate(r.Context(), ports.ApplicationVersionRequest{Application: r.PathValue("alias")})
	writeJSON(w, out, err)
}

func (s *Server) handleUpdateApplication(w http.ResponseWriter, r *http.Request) {
	var req ports.UpdateApplicationRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.UpdateApplication(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleRollbackApplication(w http.ResponseWriter, r *http.Request) {
	var req ports.RollbackApplicationRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.RollbackApplication(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	var req ports.CreateBackupRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.CreateBackup(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleVerifyBackup(w http.ResponseWriter, r *http.Request) {
	var req ports.VerifyBackupRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.VerifyBackup(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleApplyRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	var req ports.ApplyRetentionPolicyRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.ApplyRetentionPolicy(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleGenerateRestorePlan(w http.ResponseWriter, r *http.Request) {
	var req ports.RestorePlanRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.GenerateRestorePlan(r.Context(), req)
	writeJSON(w, out, err)
}

func decodeStrict(w http.ResponseWriter, r *http.Request, out any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func writeJSON(w http.ResponseWriter, value any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, fmt.Sprintf("encode response: %v", err), http.StatusInternalServerError)
	}
}
