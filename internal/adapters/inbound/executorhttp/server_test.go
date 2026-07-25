package executorhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/domain/service"
	"github.com/javiyt/safeops-mcp/internal/ports"
)

func TestHandlers(t *testing.T) {
	s := &Server{Backend: fakeBackend{}}
	cases := []struct {
		name       string
		method     string
		target     string
		body       string
		pathValues map[string]string
		handler    http.HandlerFunc
	}{
		{name: "system", method: http.MethodGet, target: "/v1/system/status", handler: s.handleSystemStatus},
		{name: "disk", method: http.MethodGet, target: "/v1/disks/root", pathValues: map[string]string{"alias": "root"}, handler: s.handleDiskStatus},
		{name: "list", method: http.MethodGet, target: "/v1/services", handler: s.handleListServices},
		{name: "status", method: http.MethodGet, target: "/v1/services/service-alpha/status", pathValues: map[string]string{"alias": "service-alpha"}, handler: s.handleServiceStatus},
		{name: "logs", method: http.MethodPost, target: "/v1/services/logs", body: `{"service":"service-alpha"}`, handler: s.handleServiceLogs},
		{name: "restart", method: http.MethodPost, target: "/v1/services/restart", body: `{"service":"service-alpha","operation_id":"op_1"}`, handler: s.handleRestartService},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			for key, value := range tc.pathValues {
				req.SetPathValue(key, value)
			}
			w := httptest.NewRecorder()
			tc.handler(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestListenAndServeOnUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "safeops-executorhttp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	socketPath := filepath.Join(dir, "s.sock")
	server := &Server{
		Config:  config.Config{Socket: config.SocketConfig{Path: socketPath, Mode: "0660"}},
		Backend: fakeBackend{},
		Listen: func(_, address string) (net.Listener, error) {
			if err := os.WriteFile(address, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return fakeListener{}, nil
		},
	}
	err = server.ListenAndServe(context.Background())
	if err == nil || !strings.Contains(err.Error(), "listener closed") {
		t.Fatalf("ListenAndServe() error = %v", err)
	}
}

func TestHandlersRejectBadJSONAndBackendErrors(t *testing.T) {
	s := &Server{Backend: fakeBackend{err: errors.New("denied")}}
	w := httptest.NewRecorder()
	s.handleSystemStatus(w, httptest.NewRequest(http.MethodGet, "/v1/system/status", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want bad request", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleServiceLogs(w, httptest.NewRequest(http.MethodPost, "/v1/services/logs", strings.NewReader("{")))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want bad request", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleRestartService(w, httptest.NewRequest(http.MethodPost, "/v1/services/restart", strings.NewReader("{")))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want bad request", w.Code)
	}
}

type fakeBackend struct {
	err error
}

type fakeListener struct{}

func (fakeListener) Accept() (net.Conn, error) {
	return nil, errors.New("listener closed")
}

func (fakeListener) Close() error {
	return nil
}

func (fakeListener) Addr() net.Addr {
	return fakeAddr("unix")
}

type fakeAddr string

func (a fakeAddr) Network() string { return string(a) }
func (a fakeAddr) String() string  { return string(a) }

func (b fakeBackend) SystemStatus(context.Context) (ports.SystemStatus, error) {
	return ports.SystemStatus{Hostname: "host-alpha"}, b.err
}
func (b fakeBackend) DiskStatus(context.Context, string) (ports.DiskStatus, error) {
	return ports.DiskStatus{PathAlias: "root"}, b.err
}
func (b fakeBackend) ListServices(context.Context) ([]ports.ServiceSummary, error) {
	return []ports.ServiceSummary{{Alias: "service-alpha", Status: "active"}}, b.err
}
func (b fakeBackend) ServiceStatus(context.Context, string) (service.Status, error) {
	return service.Status{Alias: "service-alpha", ActiveState: "active"}, b.err
}
func (b fakeBackend) ServiceLogs(context.Context, ports.ServiceLogsRequest) (ports.ServiceLogsResponse, error) {
	return ports.ServiceLogsResponse{Service: "service-alpha", UntrustedContent: true}, b.err
}
func (b fakeBackend) RestartService(context.Context, ports.RestartServiceRequest) (ports.RestartServiceResponse, error) {
	return ports.RestartServiceResponse{Status: "executed", Service: "service-alpha"}, b.err
}
