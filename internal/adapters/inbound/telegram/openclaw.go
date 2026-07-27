package telegram

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/redaction"
)

type OpenClawCLI struct {
	Command string
	Args    []string
	Timeout time.Duration
}

func NewOpenClawCLI(cfg config.TelegramOpenClawConfig) OpenClawCLI {
	return OpenClawCLI{
		Command: cfg.Command,
		Args:    append([]string(nil), cfg.Args...),
		Timeout: cfg.Timeout.Std(),
	}
}

func (c OpenClawCLI) Ask(ctx context.Context, req ConversationRequest) (ConversationResponse, error) {
	if strings.TrimSpace(c.Command) == "" {
		return ConversationResponse{}, fmt.Errorf("openclaw command is required")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(callCtx, c.Command, c.Args...)
	cmd.Env = append(os.Environ(),
		"SAFEOPS_CHANNEL=telegram",
		"SAFEOPS_TELEGRAM_USER_ID="+strconv.FormatInt(req.UserID, 10),
		"SAFEOPS_PRINCIPAL="+req.Principal,
	)
	cmd.Stdin = strings.NewReader(req.Text)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if callCtx.Err() != nil {
			return ConversationResponse{}, fmt.Errorf("openclaw request timed out")
		}
		return ConversationResponse{}, fmt.Errorf("openclaw request failed: %s", redaction.Redact(strings.TrimSpace(stderr.String())))
	}
	return parseOpenClawResponse(stdout.String()), nil
}

func parseOpenClawResponse(text string) ConversationResponse {
	clean := strings.TrimSpace(redaction.Redact(text))
	return ConversationResponse{
		Text:       clean,
		ApprovalID: firstNamedValue(clean, "approval_id"),
		Code:       firstNamedValue(clean, "confirmation_code"),
	}
}

func firstNamedValue(text, name string) string {
	for _, field := range strings.Fields(text) {
		field = strings.Trim(field, ".,;()[]{}\"'")
		if strings.HasPrefix(field, name+"=") {
			return strings.TrimPrefix(field, name+"=")
		}
		if strings.HasPrefix(field, name+":") {
			return strings.TrimPrefix(field, name+":")
		}
	}
	return ""
}
