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
	mux.HandleFunc("GET /v1/services", s.handleListServices)
	mux.HandleFunc("GET /v1/services/{alias}/status", s.handleServiceStatus)
	mux.HandleFunc("POST /v1/services/logs", s.handleServiceLogs)
	mux.HandleFunc("POST /v1/services/restart", s.handleRestartService)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.ServiceLogs(r.Context(), req)
	writeJSON(w, out, err)
}

func (s *Server) handleRestartService(w http.ResponseWriter, r *http.Request) {
	var req ports.RestartServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, nil, err)
		return
	}
	out, err := s.Backend.RestartService(r.Context(), req)
	writeJSON(w, out, err)
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
