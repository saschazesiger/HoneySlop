package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

const (
	defaultModel = "google/gemini-3.5-flash-lite"
)

var modelSuggestions = []string{
	"google/gemini-3.5-flash-lite",
	"google/gemini-3.6-flash",
	"anthropic/claude-haiku-5.5",
	"deepseek/deepseek-v4.1-flash",
	"openai/gpt-5.6-luna",
	"qwen/qwen3.8-flash",
}

// Limits are the per-IP LLM response limits.
type Limits struct {
	Minute int `json:"minute"`
	Hour   int `json:"hour"`
	Day    int `json:"day"`
	// GlobalHour caps LLM calls across all IPs per hour (wallet protection).
	GlobalHour int `json:"global_hour"`
}

// Config is persisted as config.json inside the data directory.
type Config struct {
	PasswordHash  string `json:"password_hash,omitempty"`
	SessionSecret string `json:"session_secret"`
	OpenRouterKey string `json:"openrouter_key,omitempty"`
	Model         string `json:"model"`
	AIEnabled     bool   `json:"ai_enabled"`
	Persona       string `json:"persona"`
	Limits        Limits `json:"limits"`
	TrustProxy    bool   `json:"trust_proxy"`
	// RetentionDays / MaxEvents bound the database size; oldest events are deleted first.
	RetentionDays int `json:"retention_days"`
	MaxEvents     int `json:"max_events"`
}

// ConfigStore guards the config and writes it atomically.
type ConfigStore struct {
	mu   sync.RWMutex
	path string
	c    Config
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func LoadConfig(dir string) (*ConfigStore, error) {
	s := &ConfigStore{path: filepath.Join(dir, "config.json")}
	data, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.c = Config{AIEnabled: true}
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(data, &s.c); err != nil {
			return nil, err
		}
	}
	// Fill defaults for fresh or older configs.
	if s.c.SessionSecret == "" {
		s.c.SessionSecret = randomHex(32)
	}
	if s.c.Model == "" {
		s.c.Model = defaultModel
	}
	if s.c.Persona == "" {
		s.c.Persona = defaultPersona
	}
	if s.c.Limits.Minute <= 0 {
		s.c.Limits.Minute = 10
	}
	if s.c.Limits.Hour <= 0 {
		s.c.Limits.Hour = 60
	}
	if s.c.Limits.Day <= 0 {
		s.c.Limits.Day = 100
	}
	if s.c.Limits.GlobalHour <= 0 {
		s.c.Limits.GlobalHour = 600
	}
	if s.c.RetentionDays <= 0 {
		s.c.RetentionDays = 90
	}
	if s.c.MaxEvents <= 0 {
		s.c.MaxEvents = 200_000
	}
	return s, s.saveLocked()
}

func (s *ConfigStore) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.c
}

// Update applies fn to the config and persists it.
func (s *ConfigStore) Update(fn func(c *Config)) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.c
	fn(&s.c)
	if err := s.saveLocked(); err != nil {
		s.c = old
		return old, err
	}
	return s.c, nil
}

func (s *ConfigStore) saveLocked() error {
	data, err := json.MarshalIndent(s.c, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
