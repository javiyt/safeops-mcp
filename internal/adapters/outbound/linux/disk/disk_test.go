package disk

import (
	"context"
	"testing"

	"github.com/javiyt/safeops-mcp/internal/config"
)

func TestDiskStatusUsesConfiguredAlias(t *testing.T) {
	dir := t.TempDir()
	out, err := (Reader{Config: config.Config{Filesystem: config.FilesystemConfig{DiskPaths: map[string]config.DiskPathConfig{
		"root": {Path: dir},
	}}}}).DiskStatus(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if out.PathAlias != "root" || out.Path != dir || out.TotalBytes == 0 {
		t.Fatalf("DiskStatus() = %+v", out)
	}
}
