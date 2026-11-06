package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type LLM struct {
	cfg    *ConfigStore
	client *http.Client
	sem    chan struct{} // global concurrency cap to protect the wallet
	base   string        // OpenAI compatible API base, default OpenRouter
}

func NewLLM(cfg *ConfigStore) *LLM {
	return &LLM{cfg: cfg, client: &http.Client{Timeout: 90 * time.Second}, sem: make(chan struct{}, 16),
		base: strings.TrimRight(env("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"), "/")}
}

var errAINotReady = errors.New("ai disabled or no OpenRouter key")

type llmResult struct {
	Content string
	Tokens  int
	Model   string
}

// Complete sends a chat completion to OpenRouter and returns the raw assistant content.
func (l *LLM) Complete(ctx context.Context, msgs []chatMessage, maxTokens int, force bool) (llmResult, error) {
	c := l.cfg.Get()
	if c.OpenRouterKey == "" || (!c.AIEnabled && !force) {
		return llmResult{}, errAINotReady
	}
	select {
	case l.sem <- struct{}{}:
		defer func() { <-l.sem }()
	case <-ctx.Done():
		return llmResult{}, ctx.Err()
	}
	res, status, err := l.do(ctx, c, msgs, maxTokens, true)
	if err != nil && status == http.StatusBadRequest {
		// some providers reject response_format; retry without it
		res, _, err = l.do(ctx, c, msgs, maxTokens, false)
	}
	return res, err
}

func (l *LLM) do(ctx context.Context, c Config, msgs []chatMessage, maxTokens int, jsonMode bool) (llmResult, int, error) {
	body := map[string]any{
		"model":       c.Model,
		"messages":    msgs,
		"max_tokens":  maxTokens,
		"temperature": 0.7,
	}
	if jsonMode {
		body["response_format"] = map[string]string{"type": "json_object"}
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.base+"/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return llmResult{}, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.OpenRouterKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("HTTP-Referer", "https://github.com/saschazesiger/HoneySlop")
	req.Header.Set("X-Title", "HoneySlop")
	resp, err := l.client.Do(req)
	if err != nil {
		return llmResult{}, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var out struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK || out.Error != nil {
		msg := strings.TrimSpace(string(raw))
		if out.Error != nil {
			msg = out.Error.Message
		}
		return llmResult{}, resp.StatusCode, fmt.Errorf("openrouter %d: %s", resp.StatusCode, truncate(msg, 300))
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return llmResult{}, resp.StatusCode, errors.New("openrouter: empty completion")
	}
	model := out.Model
	if model == "" {
		model = c.Model
	}
	return llmResult{Content: out.Choices[0].Message.Content, Tokens: out.Usage.TotalTokens, Model: model}, resp.StatusCode, nil
}

// extractJSON decodes the first JSON object in s (tolerates code fences / chatter around it).
func extractJSON(s string, v any) error {
	s = strings.TrimSpace(s)
	if err := json.Unmarshal([]byte(s), v); err == nil {
		return nil
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end <= start {
		return errors.New("no JSON object in completion")
	}
	return json.Unmarshal([]byte(s[start:end+1]), v)
}
