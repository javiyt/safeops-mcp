package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type HTTPAPI struct {
	Token      string
	BaseURL    string
	HTTPClient *http.Client
}

func (a HTTPAPI) GetUpdates(ctx context.Context, offset int64, timeoutSeconds int) ([]Update, error) {
	var out struct {
		OK          bool     `json:"ok"`
		Result      []Update `json:"result"`
		Description string   `json:"description"`
	}
	values := url.Values{}
	values.Set("timeout", strconv.Itoa(timeoutSeconds))
	if offset > 0 {
		values.Set("offset", strconv.FormatInt(offset, 10))
	}
	if err := a.get(ctx, "getUpdates", values, &out); err != nil {
		return nil, err
	}
	if !out.OK {
		return nil, fmt.Errorf("telegram getUpdates failed: %s", out.Description)
	}
	return out.Result, nil
}

func (a HTTPAPI) SendMessage(ctx context.Context, req SendMessageRequest) error {
	var out struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := a.post(ctx, "sendMessage", req, &out); err != nil {
		return err
	}
	if !out.OK {
		return fmt.Errorf("telegram sendMessage failed: %s", out.Description)
	}
	return nil
}

func (a HTTPAPI) AnswerCallback(ctx context.Context, callbackID, text string) error {
	var out struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	req := map[string]string{"callback_query_id": callbackID, "text": text}
	if err := a.post(ctx, "answerCallbackQuery", req, &out); err != nil {
		return err
	}
	if !out.OK {
		return fmt.Errorf("telegram answerCallbackQuery failed: %s", out.Description)
	}
	return nil
}

func (a HTTPAPI) get(ctx context.Context, method string, values url.Values, out any) error {
	endpoint := a.endpoint(method)
	if encoded := values.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	return a.do(req, out)
}

func (a HTTPAPI) post(ctx context.Context, method string, body any, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint(method), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return a.do(req, out)
}

func (a HTTPAPI) do(req *http.Request, out any) error {
	client := a.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 35 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram API returned HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (a HTTPAPI) endpoint(method string) string {
	base := a.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	return fmt.Sprintf("%s/bot%s/%s", base, a.Token, method)
}
