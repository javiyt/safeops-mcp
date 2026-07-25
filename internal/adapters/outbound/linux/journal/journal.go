package journal

import (
	"bufio"
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
	"github.com/javiyt/safeops-mcp/internal/domain/service"
)

type Reader struct {
	Runner process.Runner
}

func (r Reader) Logs(ctx context.Context, unit string, lines int, priority, since string) ([]service.LogEntry, bool, error) {
	args := []string{"-u", unit, "-n", strconv.Itoa(lines), "--output=json", "--no-pager"}
	if priority != "" {
		args = append(args, "-p", priority)
	}
	if since != "" {
		args = append(args, "--since", since)
	}
	res, err := r.Runner.Run(ctx, "/usr/bin/journalctl", args...)
	if err != nil {
		return nil, false, err
	}
	scanner := bufio.NewScanner(strings.NewReader(res.Stdout))
	var entries []service.LogEntry
	for scanner.Scan() {
		var raw map[string]any
		if json.Unmarshal(scanner.Bytes(), &raw) != nil {
			continue
		}
		entries = append(entries, service.LogEntry{
			Timestamp: asString(raw["__REALTIME_TIMESTAMP"]),
			Priority:  asString(raw["PRIORITY"]),
			Message:   asString(raw["MESSAGE"]),
		})
	}
	return entries, false, scanner.Err()
}

func asString(v any) string {
	switch value := v.(type) {
	case string:
		return value
	case float64:
		return strconv.FormatInt(int64(value), 10)
	default:
		return ""
	}
}
