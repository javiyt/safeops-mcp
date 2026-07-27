package executorclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/javiyt/safeops-mcp/internal/domain/service"
	"github.com/javiyt/safeops-mcp/internal/ports"
)

type Client struct {
	SocketPath string
	HTTP       *http.Client
}

func New(socketPath string) Client {
	return Client{SocketPath: socketPath, HTTP: &http.Client{
		Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		}},
		Timeout: 30 * time.Second,
	}}
}

func (c Client) SystemStatus(ctx context.Context) (ports.SystemStatus, error) {
	var out ports.SystemStatus
	return out, c.get(ctx, "/v1/system/status", &out)
}

func (c Client) DiskStatus(ctx context.Context, alias string) (ports.DiskStatus, error) {
	var out ports.DiskStatus
	return out, c.get(ctx, "/v1/disks/"+alias, &out)
}

func (c Client) ListServices(ctx context.Context) ([]ports.ServiceSummary, error) {
	var out struct {
		Services []ports.ServiceSummary `json:"services"`
	}
	return out.Services, c.get(ctx, "/v1/services", &out)
}

func (c Client) ServiceStatus(ctx context.Context, alias string) (service.Status, error) {
	var out service.Status
	return out, c.get(ctx, "/v1/services/"+alias+"/status", &out)
}

func (c Client) ServiceLogs(ctx context.Context, req ports.ServiceLogsRequest) (ports.ServiceLogsResponse, error) {
	var out ports.ServiceLogsResponse
	return out, c.post(ctx, "/v1/services/logs", req, &out)
}

func (c Client) RestartService(ctx context.Context, req ports.RestartServiceRequest) (ports.RestartServiceResponse, error) {
	var out ports.RestartServiceResponse
	return out, c.post(ctx, "/v1/services/restart", req, &out)
}

func (c Client) ListContainers(ctx context.Context) ([]ports.ContainerSummary, error) {
	var out struct {
		Containers []ports.ContainerSummary `json:"containers"`
	}
	return out.Containers, c.get(ctx, "/v1/containers", &out)
}

func (c Client) ContainerStatus(ctx context.Context, alias string) (ports.ContainerStatus, error) {
	var out ports.ContainerStatus
	return out, c.get(ctx, "/v1/containers/"+alias+"/status", &out)
}

func (c Client) ContainerLogs(ctx context.Context, req ports.ContainerLogsRequest) (ports.ContainerLogsResponse, error) {
	var out ports.ContainerLogsResponse
	return out, c.post(ctx, "/v1/containers/logs", req, &out)
}

func (c Client) RestartContainer(ctx context.Context, req ports.RestartContainerRequest) (ports.RestartContainerResponse, error) {
	var out ports.RestartContainerResponse
	return out, c.post(ctx, "/v1/containers/restart", req, &out)
}

func (c Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix"+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c Client) post(ctx context.Context, path string, in, out any) error {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(in); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+path, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c Client) do(req *http.Request, out any) error {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		var e map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("executor rejected request: %s", e["error"])
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
