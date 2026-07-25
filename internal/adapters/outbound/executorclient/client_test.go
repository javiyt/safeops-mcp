package executorclient

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/javiyt/safeops-mcp/internal/ports"
)

func TestClientMethods(t *testing.T) {
	client := Client{HTTP: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/v1/system/status":
			return jsonResponse(http.StatusOK, ports.SystemStatus{Hostname: "host-alpha"}), nil
		case "/v1/disks/root":
			return jsonResponse(http.StatusOK, ports.DiskStatus{PathAlias: "root"}), nil
		case "/v1/services":
			return jsonResponse(http.StatusOK, map[string]any{"services": []ports.ServiceSummary{{Alias: "service-alpha", Status: "active"}}}), nil
		case "/v1/services/service-alpha/status":
			return jsonResponse(http.StatusOK, map[string]any{"alias": "service-alpha", "unit": "app-alpha.service", "active_state": "active"}), nil
		case "/v1/services/logs":
			return jsonResponse(http.StatusOK, ports.ServiceLogsResponse{Service: "service-alpha", UntrustedContent: true}), nil
		case "/v1/services/restart":
			return jsonResponse(http.StatusOK, ports.RestartServiceResponse{Status: "executed", Service: "service-alpha"}), nil
		default:
			return jsonResponse(http.StatusNotFound, map[string]string{"error": "not found"}), nil
		}
	})}}
	ctx := context.Background()
	if out, err := client.SystemStatus(ctx); err != nil || out.Hostname != "host-alpha" {
		t.Fatalf("SystemStatus() = %+v, %v", out, err)
	}
	if out, err := client.DiskStatus(ctx, "root"); err != nil || out.PathAlias != "root" {
		t.Fatalf("DiskStatus() = %+v, %v", out, err)
	}
	if out, err := client.ListServices(ctx); err != nil || len(out) != 1 {
		t.Fatalf("ListServices() = %+v, %v", out, err)
	}
	if out, err := client.ServiceStatus(ctx, "service-alpha"); err != nil || out.ActiveState != "active" {
		t.Fatalf("ServiceStatus() = %+v, %v", out, err)
	}
	if out, err := client.ServiceLogs(ctx, ports.ServiceLogsRequest{Service: "service-alpha"}); err != nil || !out.UntrustedContent {
		t.Fatalf("ServiceLogs() = %+v, %v", out, err)
	}
	if out, err := client.RestartService(ctx, ports.RestartServiceRequest{Service: "service-alpha"}); err != nil || out.Status != "executed" {
		t.Fatalf("RestartService() = %+v, %v", out, err)
	}
}

func TestNewBuildsUnixSocketClient(t *testing.T) {
	client := New("/tmp/safeops.sock")
	if client.SocketPath != "/tmp/safeops.sock" || client.HTTP == nil {
		t.Fatalf("New() = %+v", client)
	}
}

func TestClientReturnsExecutorErrors(t *testing.T) {
	client := Client{HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "denied"}), nil
	})}}
	if _, err := client.SystemStatus(context.Background()); err == nil {
		t.Fatal("SystemStatus() error = nil, want error")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonResponse(status int, value any) *http.Response {
	data, _ := json.Marshal(value)
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       ioNopCloser{strings.NewReader(string(data))},
	}
}

type ioNopCloser struct {
	*strings.Reader
}

func (c ioNopCloser) Close() error {
	return nil
}
