package telegram

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	now      func() time.Time
	requests map[int64][]time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limit:    limit,
		window:   window,
		now:      time.Now,
		requests: map[int64][]time.Time{},
	}
}

func (r *RateLimiter) Allow(userID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.limit <= 0 {
		return false
	}
	now := r.now().UTC()
	cutoff := now.Add(-r.window)
	items := r.requests[userID]
	kept := items[:0]
	for _, item := range items {
		if item.After(cutoff) {
			kept = append(kept, item)
		}
	}
	if len(kept) >= r.limit {
		r.requests[userID] = kept
		return false
	}
	kept = append(kept, now)
	r.requests[userID] = kept
	return true
}
