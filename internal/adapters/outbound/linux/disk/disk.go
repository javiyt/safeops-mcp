package disk

import (
	"context"
	"syscall"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/ports"
)

type Reader struct {
	Config config.Config
}

func (r Reader) DiskStatus(ctx context.Context, alias string) (ports.DiskStatus, error) {
	select {
	case <-ctx.Done():
		return ports.DiskStatus{}, ctx.Err()
	default:
	}
	path := r.Config.Filesystem.DiskPaths[alias].Path
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return ports.DiskStatus{}, err
	}
	total := stat.Blocks * uint64(stat.Bsize)
	available := stat.Bavail * uint64(stat.Bsize)
	used := total - available
	percent := 0.0
	if total > 0 {
		percent = float64(used) / float64(total) * 100
	}
	return ports.DiskStatus{PathAlias: alias, Path: path, TotalBytes: total, UsedBytes: used, AvailableBytes: available, UsedPercent: percent}, nil
}
