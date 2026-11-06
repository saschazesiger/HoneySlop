package main

import (
	"encoding/json"
	"sync"
)

type sseMsg struct {
	Event string
	Data  []byte
}

// Hub fans out live updates to connected admin dashboards.
type Hub struct {
	mu   sync.Mutex
	subs map[chan sseMsg]struct{}
}

func NewHub() *Hub { return &Hub{subs: map[chan sseMsg]struct{}{}} }

func (h *Hub) Subscribe() chan sseMsg {
	ch := make(chan sseMsg, 256)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan sseMsg) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

func (h *Hub) Publish(event string, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- sseMsg{event, data}:
		default: // slow client: drop rather than block the honeypot
		}
	}
}
