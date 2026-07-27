package cpu

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/ports"
	"github.com/javiyt/safeops-mcp/internal/redaction"
)

type Reader struct {
	ProcRoot string
	SysRoot  string
	Config   config.Config
}

func (r Reader) CPUStatus(ctx context.Context) (ports.CPUStatus, error) {
	select {
	case <-ctx.Done():
		return ports.CPUStatus{}, ctx.Err()
	default:
	}
	procRoot := defaultRoot(r.ProcRoot, "/proc")
	sysRoot := defaultRoot(r.SysRoot, "/sys")
	load, err := readLoad(filepath.Join(procRoot, "loadavg"))
	if err != nil {
		return ports.CPUStatus{}, err
	}
	usage, cores, err := readCPUUsage(filepath.Join(procRoot, "stat"))
	if err != nil {
		return ports.CPUStatus{}, err
	}
	processes := readConfiguredProcesses(procRoot, r.Config)
	sort.Slice(processes, func(i, j int) bool { return processes[i].CPU > processes[j].CPU })
	if len(processes) > 5 {
		processes = processes[:5]
	}
	return ports.CPUStatus{
		UsagePercent: usage,
		Cores:        cores,
		LoadAverage:  load,
		Processes:    processes,
		FrequencyMHz: readFrequency(sysRoot, procRoot),
		Throttling:   readThrottling(sysRoot),
		Temperature:  readTemperature(sysRoot),
	}, nil
}

func defaultRoot(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func readLoad(path string) ([]float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(data))
	out := make([]float64, 0, 3)
	for i := 0; i < 3 && i < len(fields); i++ {
		v, _ := strconv.ParseFloat(fields[i], 64)
		out = append(out, v)
	}
	return out, nil
}

func readCPUUsage(path string) (float64, []ports.CoreUsage, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = f.Close() }()
	var total float64
	var cores []ports.CoreUsage
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || !strings.HasPrefix(fields[0], "cpu") {
			continue
		}
		usage := cpuLineUsage(fields[1:])
		if fields[0] == "cpu" {
			total = usage
			continue
		}
		core, err := strconv.Atoi(strings.TrimPrefix(fields[0], "cpu"))
		if err == nil {
			cores = append(cores, ports.CoreUsage{Core: core, Usage: usage})
		}
	}
	return total, cores, scanner.Err()
}

func cpuLineUsage(fields []string) float64 {
	var total, idle uint64
	for i, raw := range fields {
		v, _ := strconv.ParseUint(raw, 10, 64)
		total += v
		if i == 3 || i == 4 {
			idle += v
		}
	}
	if total == 0 {
		return 0
	}
	return float64(total-idle) / float64(total) * 100
}

func readFrequency(sysRoot, procRoot string) uint64 {
	paths := []string{
		filepath.Join(sysRoot, "devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"),
		filepath.Join(sysRoot, "devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq"),
	}
	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil {
			v, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
			return v / 1000
		}
	}
	f, err := os.Open(filepath.Join(procRoot, "cpuinfo"))
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu MHz") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				v, _ := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
				return uint64(v)
			}
		}
	}
	return 0
}

func readThrottling(sysRoot string) ports.Throttling {
	data, err := os.ReadFile(filepath.Join(sysRoot, "devices/platform/soc/soc:firmware/get_throttled"))
	if err != nil {
		return ports.Throttling{}
	}
	raw := strings.TrimSpace(string(data))
	raw = strings.TrimPrefix(raw, "0x")
	v, err := strconv.ParseUint(raw, 16, 64)
	if err != nil {
		return ports.Throttling{}
	}
	return ports.Throttling{FrequencyCapped: v&(1<<1) != 0 || v&(1<<17) != 0, Throttled: v&(1<<2) != 0 || v&(1<<18) != 0}
}

func readTemperature(sysRoot string) *float64 {
	matches, _ := filepath.Glob(filepath.Join(sysRoot, "class/thermal/thermal_zone*/temp"))
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
		if err != nil {
			continue
		}
		if v > 1000 {
			v /= 1000
		}
		return &v
	}
	return nil
}

func readConfiguredProcesses(procRoot string, cfg config.Config) []ports.ProcessUsage {
	wanted := configuredNames(cfg)
	if len(wanted) == 0 {
		return nil
	}
	uptime := readUptimeSeconds(filepath.Join(procRoot, "uptime"))
	memTotal := readMemTotalKB(filepath.Join(procRoot, "meminfo"))
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var out []ports.ProcessUsage
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		comm := readTrim(filepath.Join(procRoot, entry.Name(), "comm"))
		cmdline := strings.ReplaceAll(readTrim(filepath.Join(procRoot, entry.Name(), "cmdline")), "\x00", " ")
		cpuPercent, memPercent := readProcessUsage(filepath.Join(procRoot, entry.Name(), "stat"), uptime, memTotal)
		name := redaction.Redact(comm)
		cmd := redaction.Redact(cmdline)
		for alias, tokens := range wanted {
			if matchesProcess(alias, tokens, comm, cmdline) {
				out = append(out, ports.ProcessUsage{PID: pid, Name: name, CPU: cpuPercent, Memory: memPercent, Command: cmd, Alias: alias, Status: "running"})
				break
			}
		}
	}
	return out
}

func readUptimeSeconds(path string) float64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return v
}

func readMemTotalKB(path string) uint64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			v, _ := strconv.ParseUint(fields[1], 10, 64)
			return v
		}
	}
	return 0
}

func readProcessUsage(path string, uptime float64, memTotalKB uint64) (float64, float64) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}
	raw := string(data)
	endName := strings.LastIndex(raw, ")")
	if endName < 0 || endName+2 >= len(raw) {
		return 0, 0
	}
	fields := strings.Fields(raw[endName+2:])
	if len(fields) < 22 {
		return 0, 0
	}
	utime, _ := strconv.ParseFloat(fields[11], 64)
	stime, _ := strconv.ParseFloat(fields[12], 64)
	starttime, _ := strconv.ParseFloat(fields[19], 64)
	rssPages, _ := strconv.ParseFloat(fields[21], 64)
	clockTicks := 100.0
	seconds := uptime - (starttime / clockTicks)
	cpuPercent := 0.0
	if seconds > 0 {
		cpuPercent = ((utime + stime) / clockTicks) / seconds * 100
	}
	memPercent := 0.0
	if memTotalKB > 0 {
		rssKB := rssPages * float64(os.Getpagesize()) / 1024
		memPercent = rssKB / float64(memTotalKB) * 100
	}
	return cpuPercent, memPercent
}

func configuredNames(cfg config.Config) map[string][]string {
	out := map[string][]string{}
	for alias, svc := range cfg.Services {
		out[alias] = []string{alias, strings.TrimSuffix(svc.Unit, ".service")}
	}
	for alias, ctr := range cfg.Containers {
		out[alias] = []string{alias, ctr.ContainerName, strings.TrimSuffix(ctr.QuadletUnit, ".service")}
	}
	return out
}

func matchesProcess(alias string, tokens []string, comm, cmdline string) bool {
	haystack := strings.ToLower(comm + " " + cmdline)
	for _, token := range append(tokens, alias) {
		token = strings.ToLower(strings.TrimSpace(token))
		if token != "" && strings.Contains(haystack, token) {
			return true
		}
	}
	return false
}

func readTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
