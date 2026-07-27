package telegram

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/javiyt/safeops-mcp/internal/config"
)

func TestBotRejectsNonPrivateChatsAndUnauthorizedUsers(t *testing.T) {
	api := &fakeAPI{}
	conv := &fakeConversation{response: ConversationResponse{Text: "ok"}}
	bot := testBot(api, conv)
	if err := bot.HandleUpdate(context.Background(), Update{Message: &Message{
		Text: "hello",
		Chat: Chat{ID: -1, Type: "group"},
		From: &User{ID: 12345678},
	}}); err != nil {
		t.Fatal(err)
	}
	if len(conv.requests) != 0 || len(api.sent) != 0 {
		t.Fatal("group message reached conversation or received a reply")
	}
	if err := bot.HandleUpdate(context.Background(), Update{Message: &Message{
		Text: "hello",
		Chat: Chat{ID: 42, Type: "private"},
		From: &User{ID: 99},
	}}); err != nil {
		t.Fatal(err)
	}
	if len(conv.requests) != 0 {
		t.Fatal("unauthorized user reached conversation")
	}
	if len(api.sent) != 1 || !strings.Contains(api.sent[0].Text, "not authorized") {
		t.Fatalf("unauthorized reply = %+v", api.sent)
	}
}

func TestBotSendsAuthorizedMessagesToConversationWithPrincipal(t *testing.T) {
	api := &fakeAPI{}
	conv := &fakeConversation{response: ConversationResponse{Text: "server ok"}}
	bot := testBot(api, conv)
	if err := bot.HandleUpdate(context.Background(), Update{Message: &Message{
		Text: "How is the server?",
		Chat: Chat{ID: 42, Type: "private"},
		From: &User{ID: 12345678},
	}}); err != nil {
		t.Fatal(err)
	}
	if len(conv.requests) != 1 {
		t.Fatalf("conversation requests = %d, want 1", len(conv.requests))
	}
	if conv.requests[0].Principal != "telegram:12345678" {
		t.Fatalf("principal = %q", conv.requests[0].Principal)
	}
	if len(api.sent) != 1 || api.sent[0].Text != "server ok" {
		t.Fatalf("sent = %+v", api.sent)
	}
}

func TestBotRateLimitsPerUser(t *testing.T) {
	api := &fakeAPI{}
	conv := &fakeConversation{response: ConversationResponse{Text: "ok"}}
	bot := testBot(api, conv)
	bot.Limiter = NewRateLimiter(1, time.Minute)
	for i := 0; i < 2; i++ {
		if err := bot.HandleUpdate(context.Background(), Update{Message: &Message{
			Text: "status",
			Chat: Chat{ID: 42, Type: "private"},
			From: &User{ID: 12345678},
		}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(conv.requests) != 1 {
		t.Fatalf("conversation requests = %d, want 1", len(conv.requests))
	}
	if got := api.sent[len(api.sent)-1].Text; !strings.Contains(got, "Rate limit") {
		t.Fatalf("last message = %q", got)
	}
}

func TestBotSplitsLongResponsesAndAddsConfirmationButtons(t *testing.T) {
	api := &fakeAPI{}
	conv := &fakeConversation{response: ConversationResponse{Text: "one two three four five", ApprovalID: "apr_1", Code: "4821"}}
	bot := testBot(api, conv)
	bot.Config.Telegram.MessageSizeLimit = 8
	bot.Config.Telegram.Buttons.Enabled = true
	if err := bot.HandleUpdate(context.Background(), Update{Message: &Message{
		Text: "restart",
		Chat: Chat{ID: 42, Type: "private"},
		From: &User{ID: 12345678},
	}}); err != nil {
		t.Fatal(err)
	}
	if len(api.sent) < 2 {
		t.Fatalf("sent messages = %d, want split response", len(api.sent))
	}
	last := api.sent[len(api.sent)-1]
	if last.ReplyMarkup == nil {
		t.Fatal("confirmation buttons were not attached to final response")
	}
	if got := last.ReplyMarkup.InlineKeyboard[0][0].CallbackData; got != "confirm:apr_1:4821" {
		t.Fatalf("confirm callback = %q", got)
	}
}

func TestBotCallbackTranslatesToControlledConversationText(t *testing.T) {
	api := &fakeAPI{}
	conv := &fakeConversation{response: ConversationResponse{Text: "confirmed"}}
	bot := testBot(api, conv)
	if err := bot.HandleUpdate(context.Background(), Update{CallbackQuery: &CallbackQuery{
		ID:   "cb_1",
		From: User{ID: 12345678},
		Message: &Message{
			Chat: Chat{ID: 42, Type: "private"},
		},
		Data: "confirm:apr_1:4821",
	}}); err != nil {
		t.Fatal(err)
	}
	if len(api.answered) != 1 {
		t.Fatalf("answered callbacks = %d, want 1", len(api.answered))
	}
	if len(conv.requests) != 1 {
		t.Fatalf("conversation requests = %d, want 1", len(conv.requests))
	}
	if conv.requests[0].Text != "Confirm approval apr_1 with code 4821." {
		t.Fatalf("callback text = %q", conv.requests[0].Text)
	}
}

func testBot(api *fakeAPI, conv *fakeConversation) Bot {
	return Bot{
		Config: config.Config{
			Identity: config.IdentityConfig{AdministratorID: "telegram:12345678"},
			Telegram: config.TelegramConfig{
				Enabled:          true,
				AllowedUsers:     []int64{12345678},
				AdminID:          12345678,
				MessageSizeLimit: 4096,
				RateLimit:        config.TelegramRateLimitConfig{MessagesPerMinute: 10},
			},
		},
		API:          api,
		Conversation: conv,
	}
}

type fakeAPI struct {
	sent     []SendMessageRequest
	answered []string
}

func (f *fakeAPI) GetUpdates(context.Context, int64, int) ([]Update, error) {
	return nil, nil
}

func (f *fakeAPI) SendMessage(_ context.Context, req SendMessageRequest) error {
	f.sent = append(f.sent, req)
	return nil
}

func (f *fakeAPI) AnswerCallback(_ context.Context, callbackID, _ string) error {
	f.answered = append(f.answered, callbackID)
	return nil
}

type fakeConversation struct {
	response ConversationResponse
	requests []ConversationRequest
}

func (f *fakeConversation) Ask(_ context.Context, req ConversationRequest) (ConversationResponse, error) {
	f.requests = append(f.requests, req)
	return f.response, nil
}
