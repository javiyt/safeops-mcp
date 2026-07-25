package bootstrap

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/javiyt/safeops-mcp/internal/config"
)

func TestNewToolServiceMigratesStore(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		Database: config.DatabaseConfig{Path: filepath.Join(dir, "safeops.db")},
		Socket:   config.SocketConfig{Path: filepath.Join(dir, "safeops.sock")},
	}
	svc, closeFn, err := NewToolService(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = closeFn()
	}()
	if svc.Approvals == nil || svc.Audit == nil || svc.Executor == nil {
		t.Fatalf("service not initialized: %+v", svc)
	}
}
