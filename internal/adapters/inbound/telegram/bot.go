package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/domain/audit"
	"github.com/javiyt/safeops-mcp/internal/ports"
	"github.com/javiyt/safeops-mcp/internal/redaction"
)

type API interface {
	GetUpdates(ctx context.Context, offset int64, timeoutSeconds int) ([]Update, error)
	SendMessage(ctx context.Context, req SendMessageRequest) error
	AnswerCallback(ctx context.Context, callbackID, text string) error
}

type ConversationClient interface {
	Ask(ctx context.Context, req ConversationRequest) (ConversationResponse, error)
}

type ConversationRequest struct {
	UserID    int64
	ChatID    int64
	Principal string
	Text      string
}

type ConversationResponse struct {
	Text       string
	ApprovalID string
	Code       string
}

type Bot struct {
	Config       config.Config
	API          API
	Conversation ConversationClient
	Audit        ports.AuditRepository
	IDs          ports.IDGenerator
	Clock        ports.Clock
	Limiter      *RateLimiter
	Logger       *slog.Logger
}

func (b Bot) Serve(ctx context.Context) error {
	offset := int64(0)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		updates, err := b.API.GetUpdates(ctx, offset, 30)
		if err != nil {
			b.log("telegram_poll_error", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
				continue
			}
		}
		for _, update := range updates {
			if update.UpdateID >= offset {
				offset = update.UpdateID + 1
			}
			if err := b.HandleUpdate(ctx, update); err != nil {
				b.log("telegram_update_error", err)
			}
		}
	}
}

func (b Bot) HandleUpdate(ctx context.Context, update Update) error {
	if update.Message != nil {
		return b.handleMessage(ctx, *update.Message)
	}
	if update.CallbackQuery != nil {
		return b.handleCallback(ctx, *update.CallbackQuery)
	}
	return nil
}

func (b Bot) handleMessage(ctx context.Context, msg Message) error {
	if msg.From == nil {
		return nil
	}
	if msg.Chat.Type != "private" {
		_ = b.audit(ctx, msg.From.ID, "telegram_rejected", "non_private_chat", "rejected", "")
		return nil
	}
	if !b.allowed(msg.From.ID) {
		_ = b.audit(ctx, msg.From.ID, "telegram_rejected", "unauthorized_user", "rejected", "")
		return b.API.SendMessage(ctx, SendMessageRequest{ChatID: msg.Chat.ID, Text: "This Telegram user is not authorized for SafeOps."})
	}
	if !b.limit(msg.From.ID) {
		_ = b.audit(ctx, msg.From.ID, "telegram_rate_limited", "message", "rejected", "")
		return b.API.SendMessage(ctx, SendMessageRequest{ChatID: msg.Chat.ID, Text: "Rate limit exceeded. Try again later."})
	}
	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return nil
	}
	if len([]rune(text)) > b.Config.Telegram.MessageSizeLimit {
		_ = b.audit(ctx, msg.From.ID, "telegram_rejected", "message_too_large", "rejected", "")
		return b.API.SendMessage(ctx, SendMessageRequest{ChatID: msg.Chat.ID, Text: "Message is too long."})
	}
	if text == "/start" {
		_ = b.audit(ctx, msg.From.ID, "telegram_start", "start", "accepted", "")
		return b.API.SendMessage(ctx, SendMessageRequest{ChatID: msg.Chat.ID, Text: "SafeOps is ready. Messages in this private chat are audited."})
	}
	_ = b.audit(ctx, msg.From.ID, "telegram_message_received", "message", "accepted", "")
	resp, err := b.Conversation.Ask(ctx, ConversationRequest{
		UserID:    msg.From.ID,
		ChatID:    msg.Chat.ID,
		Principal: b.Config.TelegramPrincipal(),
		Text:      text,
	})
	if err != nil {
		_ = b.audit(ctx, msg.From.ID, "telegram_openclaw_error", "message", "failed", err.Error())
		return b.API.SendMessage(ctx, SendMessageRequest{ChatID: msg.Chat.ID, Text: redaction.Redact(err.Error())})
	}
	_ = b.audit(ctx, msg.From.ID, "telegram_response_sent", "message", "accepted", "")
	return b.sendResponse(ctx, msg.Chat.ID, resp)
}

func (b Bot) handleCallback(ctx context.Context, cb CallbackQuery) error {
	if !b.allowed(cb.From.ID) {
		_ = b.audit(ctx, cb.From.ID, "telegram_callback_rejected", "unauthorized_user", "rejected", "")
		return b.API.AnswerCallback(ctx, cb.ID, "Not authorized.")
	}
	if cb.Message == nil || cb.Message.Chat.Type != "private" {
		_ = b.audit(ctx, cb.From.ID, "telegram_callback_rejected", "non_private_chat", "rejected", "")
		return b.API.AnswerCallback(ctx, cb.ID, "Rejected.")
	}
	if !b.limit(cb.From.ID) {
		_ = b.audit(ctx, cb.From.ID, "telegram_rate_limited", "callback", "rejected", "")
		return b.API.AnswerCallback(ctx, cb.ID, "Rate limit exceeded.")
	}
	text, err := callbackText(cb.Data)
	if err != nil {
		_ = b.audit(ctx, cb.From.ID, "telegram_callback_rejected", "invalid_callback", "rejected", err.Error())
		return b.API.AnswerCallback(ctx, cb.ID, "Invalid callback.")
	}
	if err := b.API.AnswerCallback(ctx, cb.ID, "Received."); err != nil {
		return err
	}
	_ = b.audit(ctx, cb.From.ID, "telegram_callback_received", "callback", "accepted", "")
	resp, err := b.Conversation.Ask(ctx, ConversationRequest{
		UserID:    cb.From.ID,
		ChatID:    cb.Message.Chat.ID,
		Principal: b.Config.TelegramPrincipal(),
		Text:      text,
	})
	if err != nil {
		_ = b.audit(ctx, cb.From.ID, "telegram_openclaw_error", "callback", "failed", err.Error())
		return b.API.SendMessage(ctx, SendMessageRequest{ChatID: cb.Message.Chat.ID, Text: redaction.Redact(err.Error())})
	}
	return b.sendResponse(ctx, cb.Message.Chat.ID, resp)
}

func (b Bot) sendResponse(ctx context.Context, chatID int64, resp ConversationResponse) error {
	limit := b.Config.Telegram.MessageSizeLimit
	if limit <= 0 || limit > 4096 {
		limit = 4096
	}
	parts := splitMessage(resp.Text, limit)
	if len(parts) == 0 {
		parts = []string{"No response."}
	}
	for i, part := range parts {
		req := SendMessageRequest{ChatID: chatID, Text: part}
		if i == len(parts)-1 && b.Config.Telegram.Buttons.Enabled && resp.ApprovalID != "" {
			req.ReplyMarkup = confirmationButtons(resp.ApprovalID, resp.Code)
		}
		if err := b.API.SendMessage(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

func confirmationButtons(approvalID, code string) *InlineKeyboardMarkup {
	return &InlineKeyboardMarkup{InlineKeyboard: [][]InlineKeyboardButton{{
		{Text: "Confirm", CallbackData: "confirm:" + approvalID + ":" + code},
		{Text: "Cancel", CallbackData: "cancel:" + approvalID},
	}}}
}

func callbackText(data string) (string, error) {
	parts := strings.Split(data, ":")
	switch {
	case len(parts) == 3 && parts[0] == "confirm" && parts[1] != "" && parts[2] != "":
		return fmt.Sprintf("Confirm approval %s with code %s.", parts[1], parts[2]), nil
	case len(parts) == 2 && parts[0] == "cancel" && parts[1] != "":
		return fmt.Sprintf("Cancel approval %s.", parts[1]), nil
	default:
		return "", fmt.Errorf("unsupported callback data")
	}
}

func splitMessage(text string, limit int) []string {
	text = redaction.Redact(strings.TrimSpace(text))
	if text == "" {
		return nil
	}
	runes := []rune(text)
	var out []string
	for len(runes) > limit {
		cut := limit
		for cut > 0 && runes[cut-1] != '\n' && runes[cut-1] != ' ' {
			cut--
		}
		if cut == 0 {
			cut = limit
		}
		out = append(out, strings.TrimSpace(string(runes[:cut])))
		runes = runes[cut:]
	}
	out = append(out, strings.TrimSpace(string(runes)))
	return out
}

func (b Bot) allowed(userID int64) bool {
	for _, allowed := range b.Config.Telegram.AllowedUsers {
		if userID == allowed {
			return true
		}
	}
	return false
}

func (b Bot) limit(userID int64) bool {
	if b.Limiter == nil {
		return true
	}
	return b.Limiter.Allow(userID)
}

func (b Bot) audit(ctx context.Context, telegramUserID int64, eventType, action, status, errSummary string) error {
	if b.Audit == nil || b.IDs == nil || b.Clock == nil {
		return nil
	}
	id, err := b.IDs.NewID("aud")
	if err != nil {
		return err
	}
	args, err := json.Marshal(map[string]string{"telegram_user_id": strconv.FormatInt(telegramUserID, 10)})
	if err != nil {
		return err
	}
	return b.Audit.Append(ctx, audit.Event{
		ID:             id,
		Timestamp:      b.Clock.Now(),
		UserID:         "telegram:" + strconv.FormatInt(telegramUserID, 10),
		Component:      "safeops-telegram",
		EventType:      eventType,
		Tool:           "telegram",
		Action:         action,
		Arguments:      string(args),
		Risk:           "channel",
		PolicyDecision: "allowlist",
		Status:         status,
		ErrorSummary:   redaction.Redact(errSummary),
	})
}

func (b Bot) log(message string, err error) {
	if b.Logger != nil {
		b.Logger.Error(message, "error", err)
	}
}
