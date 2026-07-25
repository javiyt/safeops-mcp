package healthcheck

import (
	"context"
	"io"
	"net/http"
	"time"
)

type Client struct {
	MaxBodyBytes int64
	HTTP         HTTPDoer
}

type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

func (c Client) Check(ctx context.Context, url string, timeout time.Duration, attempts int, interval time.Duration) (bool, int) {
	for attempt := 1; attempt <= attempts; attempt++ {
		ok := c.once(ctx, url, timeout)
		if ok {
			return true, attempt
		}
		select {
		case <-ctx.Done():
			return false, attempt
		case <-time.After(interval):
		}
	}
	return false, attempts
}

func (c Client) once(ctx context.Context, rawURL string, timeout time.Duration) bool {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := c.HTTP
	if client == nil {
		client = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 0 && req.URL.Host != via[0].URL.Host {
					return http.ErrUseLastResponse
				}
				if len(via) >= 2 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	_, _ = io.CopyN(io.Discard, resp.Body, c.MaxBodyBytes)
	return resp.StatusCode >= 200 && resp.StatusCode <= 299
}
