package git

import (
	"context"
	"errors"
	"strings"

	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
	"github.com/javiyt/safeops-mcp/internal/redaction"
)

type Client struct {
	Binary string
	Runner process.Runner
}

func (c Client) binary() string {
	if c.Binary == "" {
		return "/usr/bin/git"
	}
	return c.Binary
}

func (c Client) RemoteCommit(ctx context.Context, repositoryURL, branch string) (string, error) {
	res, err := c.Runner.Run(ctx, c.binary(), "ls-remote", repositoryURL, "refs/heads/"+branch)
	if err != nil {
		return "", errors.New(redaction.Redact(err.Error()))
	}
	fields := strings.Fields(res.Stdout)
	if len(fields) == 0 {
		return "", errors.New("remote branch was not found")
	}
	return fields[0], nil
}

func (c Client) CurrentCommit(ctx context.Context, repositoryPath string) (string, error) {
	res, err := c.Runner.Run(ctx, c.binary(), "-C", repositoryPath, "rev-parse", "HEAD")
	if err != nil {
		return "", errors.New(redaction.Redact(err.Error()))
	}
	return strings.TrimSpace(res.Stdout), nil
}

func (c Client) Fetch(ctx context.Context, repositoryPath, branch string) error {
	_, err := c.Runner.Run(ctx, c.binary(), "-C", repositoryPath, "fetch", "--prune", "origin", "refs/heads/"+branch)
	if err != nil {
		return errors.New(redaction.Redact(err.Error()))
	}
	return nil
}

func (c Client) CheckoutCommit(ctx context.Context, repositoryPath, commit string) error {
	_, err := c.Runner.Run(ctx, c.binary(), "-C", repositoryPath, "checkout", "--detach", commit)
	if err != nil {
		return errors.New(redaction.Redact(err.Error()))
	}
	return nil
}
