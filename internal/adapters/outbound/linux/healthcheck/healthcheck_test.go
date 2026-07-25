package healthcheck

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCheckSucceedsOnHealthyStatus(t *testing.T) {
	healthy, attempts := (Client{MaxBodyBytes: 16, HTTP: fakeDoer{statuses: []int{http.StatusNoContent}}}).Check(context.Background(), "http://127.0.0.1/health", time.Second, 2, time.Millisecond)
	if !healthy || attempts != 1 {
		t.Fatalf("healthy=%v attempts=%d", healthy, attempts)
	}
}

func TestCheckRetriesAndFails(t *testing.T) {
	healthy, attempts := (Client{MaxBodyBytes: 16, HTTP: fakeDoer{statuses: []int{http.StatusInternalServerError, http.StatusInternalServerError}}}).Check(context.Background(), "http://127.0.0.1/health", time.Second, 2, time.Millisecond)
	if healthy || attempts != 2 {
		t.Fatalf("healthy=%v attempts=%d", healthy, attempts)
	}
}

func TestCheckHandlesInvalidURLAndHTTPError(t *testing.T) {
	if healthy, attempts := (Client{}).Check(context.Background(), ":", time.Second, 1, time.Millisecond); healthy || attempts != 1 {
		t.Fatalf("healthy=%v attempts=%d", healthy, attempts)
	}
	if healthy, attempts := (Client{HTTP: errorDoer{}}).Check(context.Background(), "http://127.0.0.1/health", time.Second, 1, time.Millisecond); healthy || attempts != 1 {
		t.Fatalf("healthy=%v attempts=%d", healthy, attempts)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if healthy, attempts := (Client{HTTP: fakeDoer{statuses: []int{http.StatusInternalServerError}}}).Check(ctx, "http://127.0.0.1/health", time.Second, 2, time.Hour); healthy || attempts != 1 {
		t.Fatalf("healthy=%v attempts=%d", healthy, attempts)
	}
}

type fakeDoer struct {
	statuses []int
}

func (d fakeDoer) Do(*http.Request) (*http.Response, error) {
	status := d.statuses[0]
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader("body")),
	}, nil
}

type errorDoer struct{}

func (errorDoer) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("network denied")
}
