package network

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/ports"
)

type Reader struct {
	ProcRoot string
	SysRoot  string
	Config   config.Config
	Runner   process.Runner
	PingPath string
}

func (r Reader) NetworkStatus(ctx context.Context) (ports.NetworkStatus, error) {
	select {
	case <-ctx.Done():
		return ports.NetworkStatus{}, ctx.Err()
	default:
	}
	ifaces, err := r.interfaces()
	if err != nil {
		return ports.NetworkStatus{}, err
	}
	conn := make([]ports.ConnectivityResult, 0, len(r.Config.Diagnostics.Network.PingTargets))
	for _, target := range r.Config.Diagnostics.Network.PingTargets {
		conn = append(conn, r.ping(ctx, target))
	}
	return ports.NetworkStatus{Interfaces: ifaces, Connectivity: conn}, nil
}

func (r Reader) interfaces() ([]ports.NetworkInterface, error) {
	sysRoot := r.SysRoot
	if sysRoot == "" {
		sysRoot = "/sys"
	}
	procRoot := r.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	dns := readDNS("/etc/resolv.conf", r.Config.Diagnostics.Network.RedactIPs)
	gateway := readGateway(filepath.Join(procRoot, "net/route"), r.Config.Diagnostics.Network.RedactIPs)
	netIfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]ports.NetworkInterface, 0, len(netIfaces))
	for _, iface := range netIfaces {
		state := "down"
		if iface.Flags&net.FlagUp != 0 {
			state = "up"
		}
		ip := firstIPv4(iface, r.Config.Diagnostics.Network.RedactIPs)
		out = append(out, ports.NetworkInterface{
			Name:    iface.Name,
			State:   state,
			IP:      ip,
			Gateway: gateway,
			DNS:     dns,
			Errors:  readUint(filepath.Join(sysRoot, "class/net", iface.Name, "statistics/rx_errors")) + readUint(filepath.Join(sysRoot, "class/net", iface.Name, "statistics/tx_errors")),
			Dropped: readUint(filepath.Join(sysRoot, "class/net", iface.Name, "statistics/rx_dropped")) + readUint(filepath.Join(sysRoot, "class/net", iface.Name, "statistics/tx_dropped")),
		})
	}
	return out, nil
}

func (r Reader) ping(ctx context.Context, target string) ports.ConnectivityResult {
	result := ports.ConnectivityResult{Target: redactIP(target, r.Config.Diagnostics.Network.RedactIPs)}
	path := r.PingPath
	if path == "" {
		path = "/bin/ping"
	}
	if r.Runner == nil {
		return result
	}
	out, err := r.Runner.Run(ctx, path, "-c", "1", "-W", "1", target)
	if err != nil {
		return result
	}
	result.Reachable = true
	if latency := parseLatency(out.Stdout); latency != nil {
		result.LatencyMS = latency
	}
	return result
}

func firstIPv4(iface net.Interface, redact bool) string {
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && ip.To4() != nil {
			return redactIP(ip.String(), redact)
		}
	}
	return ""
}

func readDNS(path string, redact bool) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "nameserver" {
			out = append(out, redactIP(fields[1], redact))
		}
	}
	return out
}

func readGateway(path string, redact bool) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "00000000" {
			v, err := strconv.ParseUint(fields[2], 16, 32)
			if err != nil {
				continue
			}
			ip := net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).String()
			return redactIP(ip, redact)
		}
	}
	return ""
}

func readUint(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return v
}

func parseLatency(out string) *float64 {
	idx := strings.Index(out, "time=")
	if idx < 0 {
		return nil
	}
	rest := out[idx+len("time="):]
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return nil
	}
	v, err := strconv.ParseFloat(strings.TrimSuffix(fields[0], "ms"), 64)
	if err != nil {
		return nil
	}
	return &v
}

func redactIP(value string, redact bool) string {
	if !redact || net.ParseIP(value) == nil {
		return value
	}
	return "[REDACTED_IP]"
}
