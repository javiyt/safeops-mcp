package bootstrap

import (
	"context"
	"log/slog"

	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/executorclient"
	sqlitestore "github.com/javiyt/safeops-mcp/internal/adapters/outbound/sqlite"
	"github.com/javiyt/safeops-mcp/internal/application/tools"
	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/domain/policy"
)

func NewToolService(ctx context.Context, cfg config.Config, logger *slog.Logger) (tools.Service, func() error, error) {
	_ = logger
	store, err := sqlitestore.Open(cfg.Database.Path)
	if err != nil {
		return tools.Service{}, nil, err
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close()
		return tools.Service{}, nil, err
	}
	return tools.Service{
		Config:      cfg,
		Executor:    executorclient.New(cfg.Socket.Path),
		Approvals:   store,
		Alerts:      store,
		Deployments: store,
		Backups:     store,
		Audit:       store,
		Clock:       SystemClock{},
		IDs:         CryptoIDGenerator{},
		Codes:       CryptoCodeGenerator{},
		Policy:      policy.Engine{DryRun: cfg.Policies.DryRun},
	}, store.Close, nil
}
