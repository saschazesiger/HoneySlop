package main

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"pot.example.com":            "pot.example.com",
		"https://Pot.Example.com/x":  "pot.example.com",
		"http://pot.example.com:443": "pot.example.com",
		"":                           "",
	} {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractJSON(t *testing.T) {
	var v struct{ Status int }
	if err := extractJSON("```json\n{\"status\": 403}\n```", &v); err != nil || v.Status != 403 {
		t.Fatalf("got %v %v", v, err)
	}
	if err := extractJSON("no json here", &v); err == nil {
		t.Fatal("expected error")
	}
}

func TestTruncateUTF8(t *testing.T) {
	if got := truncate("äöü", 3); got != "ä" {
		t.Fatalf("got %q", got)
	}
}

func TestRateLimit(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	rl := NewRateLimiter(cfg)
	for i := 0; i < 10; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d unexpectedly limited", i)
		}
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("11th request in a minute should be limited")
	}
	if !rl.Allow("5.6.7.8") {
		t.Fatal("other IPs must not be affected")
	}
	for i := 0; i < 10; i++ {
		rl.Allow(fmt.Sprintf("2001:db8:1:2::%x", i+1))
	}
	if rl.Allow("2001:db8:1:2:ffff::1") {
		t.Fatal("IPv6 addresses of the same /64 must share a budget")
	}
}

func TestPrune(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		ts := time.Now().UnixMilli()
		if i == 0 {
			ts = time.Now().Add(-48 * time.Hour).UnixMilli()
		}
		if _, _, err := store.InsertEvent(&Event{TS: ts, IP: "1.2.3.4", Kind: "http"}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := store.Prune(24*time.Hour, 3)
	if err != nil || n != 2 {
		t.Fatalf("pruned %d, err %v; want 2", n, err)
	}
}
