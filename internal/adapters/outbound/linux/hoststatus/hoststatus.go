package hoststatus

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/javiyt/safeops-mcp/internal/ports"
)

type Reader struct {
	ProcRoot string
	Hostname func() (string, error)
	NumCPU   func() int
	GOOS     string
	GOARCH   string
}

func (r Reader) SystemStatus(ctx context.Context) (ports.SystemStatus, error) {
	select {
	case <-ctx.Done():
		return ports.SystemStatus{}, ctx.Err()
	default:
	}
	hostnameFunc := r.Hostname
	if hostnameFunc == nil {
		hostnameFunc = os.Hostname
	}
	hostname, _ := hostnameFunc()
	procRoot := r.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	load, err := readLoad(filepath.Join(procRoot, "loadavg"))
	if err != nil {
		return ports.SystemStatus{}, err
	}
	uptime, err := readUptime(filepath.Join(procRoot, "uptime"))
	if err != nil {
		return ports.SystemStatus{}, err
	}
	mem, err := readMemory(filepath.Join(procRoot, "meminfo"))
	if err != nil {
		return ports.SystemStatus{}, err
	}
	numCPU := r.NumCPU
	if numCPU == nil {
		numCPU = runtime.NumCPU
	}
	goos := r.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := r.GOARCH
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	return ports.SystemStatus{
		Hostname:      hostname,
		UptimeSeconds: uptime,
		LoadAverage:   load,
		Memory:        mem,
		CPU:           ports.CPU{Cores: numCPU(), Architecture: goarch},
		Kernel:        goos,
	}, nil
}

func readLoad(path string) (ports.LoadAverage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ports.LoadAverage{}, err
	}
	fields := strings.Fields(string(data))
	one, _ := strconv.ParseFloat(fields[0], 64)
	five, _ := strconv.ParseFloat(fields[1], 64)
	fifteen, _ := strconv.ParseFloat(fields[2], 64)
	return ports.LoadAverage{OneMinute: one, FiveMinutes: five, FifteenMinutes: fifteen}, nil
}

func readUptime(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	first := strings.Fields(string(data))[0]
	value, err := strconv.ParseFloat(first, 64)
	return uint64(value), err
}

func readMemory(path string) (ports.Memory, error) {
	f, err := os.Open(path)
	if err != nil {
		return ports.Memory{}, err
	}
	defer func() {
		_ = f.Close()
	}()
	values := map[string]uint64{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			v, _ := strconv.ParseUint(fields[1], 10, 64)
			values[strings.TrimSuffix(fields[0], ":")] = v * 1024
		}
	}
	if err := scanner.Err(); err != nil {
		return ports.Memory{}, err
	}
	total := values["MemTotal"]
	available := values["MemAvailable"]
	usedPercent := 0.0
	if total > 0 {
		usedPercent = float64(total-available) / float64(total) * 100
	}
	return ports.Memory{TotalBytes: total, AvailableBytes: available, UsedPercent: usedPercent}, nil
}
