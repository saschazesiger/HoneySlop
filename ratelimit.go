package main

import (
	"net"
	"sync"
	"time"
)

// limitKey groups IPv6 clients by /64 so an attacker can't rotate through a prefix.
func limitKey(ip string) string {
	p := net.ParseIP(ip)
	if p == nil || p.To4() != nil {
		return ip
	}
	return p.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// RateLimiter enforces the per-IP LLM budget (minute/hour/day) plus a global hourly cap.
// A slot is consumed at reservation time, so slow or stalled clients can't overshoot.
type RateLimiter struct {
	cfg    *ConfigStore
	mu     sync.Mutex
	hits   map[string][]time.Time
	global []time.Time
}

func NewRateLimiter(cfg *ConfigStore) *RateLimiter {
	return &RateLimiter{cfg: cfg, hits: map[string][]time.Time{}}
}

func prune(ts []time.Time, cut time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cut) {
		i++
	}
	return ts[i:]
}

// Allow reports whether the IP may use the LLM now and, if so, consumes one slot.
func (r *RateLimiter) Allow(ip string) bool {
	lim := r.cfg.Get().Limits
	now := time.Now()
	key := limitKey(ip)
	r.mu.Lock()
	defer r.mu.Unlock()

	r.global = prune(r.global, now.Add(-time.Hour))
	if lim.GlobalHour > 0 && len(r.global) >= lim.GlobalHour {
		return false
	}
	h := prune(r.hits[key], now.Add(-24*time.Hour))
	r.hits[key] = h
	count := func(d time.Duration) int {
		cut, n := now.Add(-d), 0
		for _, t := range h {
			if t.After(cut) {
				n++
			}
		}
		return n
	}
	if len(h) >= lim.Day || count(time.Hour) >= lim.Hour || count(time.Minute) >= lim.Minute {
		return false
	}
	r.hits[key] = append(h, now)
	r.global = append(r.global, now)
	return true
}

// Sweep drops idle entries (called periodically).
func (r *RateLimiter) Sweep() {
	cut := time.Now().Add(-24 * time.Hour)
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range r.hits {
		if len(prune(v, cut)) == 0 {
			delete(r.hits, k)
		}
	}
}

// LoginLimiter throttles admin password attempts per IP (in memory).
type LoginLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func NewLoginLimiter() *LoginLimiter { return &LoginLimiter{hits: map[string][]time.Time{}} }

func (l *LoginLimiter) Allow(ip string) bool {
	key := limitKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	h := prune(l.hits[key], time.Now().Add(-10*time.Minute))
	if len(h) >= 10 {
		l.hits[key] = h
		return false
	}
	l.hits[key] = append(h, time.Now())
	return true
}

func (l *LoginLimiter) Sweep() {
	cut := time.Now().Add(-10 * time.Minute)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, v := range l.hits {
		if len(prune(v, cut)) == 0 {
			delete(l.hits, k)
		}
	}
}
