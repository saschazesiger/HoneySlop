package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/saschazesiger/honeyslop/web"
)

const (
	termHost        = "web-prod-03"
	termDefaultUser = "www-data"
	termDefaultCwd  = "/var/www/connect/public"
	termCookie      = "PHPSESSID"
	maxHistoryChars = 150_000 // keep the whole history unless it gets absurdly large
	maxHistoryCmds  = 400     // commands per session kept for replay/context
)

type termLine struct {
	Cmd    string `json:"cmd"`
	Output string `json:"output"`
	Cwd    string `json:"cwd"`
	User   string `json:"user"`
}

type termState struct {
	Cwd  string `json:"cwd"`
	User string `json:"user"`
}

func newSessionID() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 26)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func validSessionID(s string) bool {
	if len(s) != 26 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func (a *App) termSession(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(termCookie); err == nil && validSessionID(c.Value) {
		return c.Value
	}
	sid := newSessionID()
	http.SetCookie(w, &http.Cookie{Name: termCookie, Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return sid
}

// state after each event is stored in the event's response headers (X-Cwd / X-User)
func stateAfter(e Event) termState {
	st := termState{Cwd: e.RespHeaders.Get("X-Cwd"), User: e.RespHeaders.Get("X-User")}
	if st.Cwd == "" {
		st.Cwd = e.Cwd
	}
	if st.User == "" {
		st.User = termDefaultUser
	}
	return st
}

func (a *App) handleTerminalPage(w http.ResponseWriter, r *http.Request) {
	sid := a.termSession(w, r)
	hist, _ := a.store.TerminalHistory(sid, maxHistoryCmds)
	state := termState{Cwd: termDefaultCwd, User: termDefaultUser}
	lines := make([]termLine, 0, len(hist))
	for _, e := range hist {
		before := state
		state = stateAfter(e)
		lines = append(lines, termLine{Cmd: e.Cmd, Output: e.RespBody, Cwd: before.Cwd, User: before.User})
	}
	boot, _ := json.Marshal(map[string]any{
		"host": termHost, "cwd": state.Cwd, "user": state.User, "history": lines, "motd": motd(),
	})
	page := strings.Replace(web.TerminalHTML, "{{BOOT}}", string(boot), 1)

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Server", serverHeader)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(page))

	ev := a.newEvent(r, "page", "")
	ev.Status, ev.Source, ev.Session = 200, "static", sid
	ev.RespHeaders = w.Header().Clone()
	ev.RespBody = "[web terminal page served]"
	a.record(ev)
}

func motd() string {
	now := time.Now().UTC()
	last := now.Add(-time.Duration(19+now.Day()%5) * time.Hour).Add(-37 * time.Minute)
	return fmt.Sprintf(`Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-169-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of %s

  System load:  0.41               Processes:             287
  Usage of /:   71.3%% of 96.73GB   Users logged in:       1
  Memory usage: 63%%                IPv4 address for ens160: 10.20.2.43
  Swap usage:   4%%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

47 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

*** System restart required ***
Last login: %s from 10.20.1.15`, now.Format("Mon 02 Jan 2006 03:04:05 PM UTC"), last.Format("Mon Jan  2 15:04:05 2006"))
}

// handleTerminalCommand executes one command of the fake shell (POST / with JSON).
func (a *App) handleTerminalCommand(w http.ResponseWriter, r *http.Request, body string) {
	var in struct {
		Cmd string `json:"cmd"`
	}
	_ = json.Unmarshal([]byte(body), &in)
	cmd := strings.TrimSpace(truncate(in.Cmd, 4000))
	sid := a.termSession(w, r)
	start := time.Now()

	hist, _ := a.store.TerminalHistory(sid, maxHistoryCmds)
	state := termState{Cwd: termDefaultCwd, User: termDefaultUser}
	if len(hist) > 0 {
		state = stateAfter(hist[len(hist)-1])
	}

	reqBody, _ := json.Marshal(map[string]string{"cmd": cmd}) // store only what matters, not padding
	ev := a.newEvent(r, "terminal", string(reqBody))
	ev.Method, ev.Path, ev.Cmd, ev.Cwd, ev.Session = "SHELL", "/", cmd, state.Cwd, sid
	next := state
	var output string

	cfg := a.cfg.Get()
	switch first := strings.Fields(cmd + " x")[0]; {
	case cmd == "":
		ev.Source = "static"
	case first == "exit" || first == "logout":
		ev.Source, output = "static", "logout"
	case cmd == "pwd":
		ev.Source, output = "static", state.Cwd
	case cmd == "whoami":
		ev.Source, output = "static", state.User
	case cmd == "hostname":
		ev.Source, output = "static", termHost
	case !cfg.AIEnabled || cfg.OpenRouterKey == "":
		ev.Source, output = "disabled", "-bash: fork: retry: Resource temporarily unavailable"
	default:
		if !a.limiter.Allow(ev.IP) {
			ev.Source, output = "ratelimited", "-bash: fork: retry: Resource temporarily unavailable"
			break
		}
		res, out, err := a.generateTerminal(r.Context(), hist, state, cmd)
		if err != nil {
			log.Printf("llm terminal %s: %v", ev.IP, err)
			ev.Source, output = "error", "-bash: fork: Cannot allocate memory"
			break
		}
		ev.Source, ev.Model, ev.Tokens = "ai", res.Model, res.Tokens
		output = out.Output
		if strings.HasPrefix(out.Cwd, "/") {
			next.Cwd = out.Cwd
		}
		if u := strings.TrimSpace(out.User); u != "" && !strings.ContainsAny(u, " /\n") {
			next.User = u
		}
	}

	resp := map[string]string{"output": output, "cwd": next.Cwd, "user": next.User}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", serverHeader)
	_ = json.NewEncoder(w).Encode(resp)

	ev.Status = 200
	ev.RespHeaders = http.Header{"X-Cwd": {next.Cwd}, "X-User": {next.User}}
	ev.RespBody = output
	ev.LatencyMS = time.Since(start).Milliseconds()
	a.record(ev)
}

type termReply struct {
	Output string `json:"output"`
	Cwd    string `json:"cwd"`
	User   string `json:"user"`
}

func (a *App) generateTerminal(ctx context.Context, hist []Event, state termState, cmd string) (llmResult, termReply, error) {
	cfg := a.cfg.Get()
	sys := strings.NewReplacer("{{PERSONA}}", cfg.Persona, "{{DATE}}", time.Now().UTC().Format("Mon Jan 2 15:04:05 UTC 2006")).
		Replace(terminalSystemPrompt)

	prompt := func(user, cwd, c string) string {
		return fmt.Sprintf("[user=%s cwd=%s]\n$ %s", user, cwd, c)
	}
	// Full history as alternating turns, so the shell remembers everything that happened.
	var turns []chatMessage
	st := termState{Cwd: termDefaultCwd, User: termDefaultUser}
	for _, e := range hist {
		if e.Cmd == "" {
			continue
		}
		after := stateAfter(e)
		reply, _ := json.Marshal(termReply{Output: e.RespBody, Cwd: after.Cwd, User: after.User})
		turns = append(turns, chatMessage{"user", prompt(st.User, e.Cwd, e.Cmd)}, chatMessage{"assistant", string(reply)})
		st = after
	}
	size := 0
	for _, t := range turns {
		size += len(t.Content)
	}
	for size > maxHistoryChars && len(turns) >= 2 {
		size -= len(turns[0].Content) + len(turns[1].Content)
		turns = turns[2:]
	}
	msgs := append([]chatMessage{{"system", sys}}, turns...)
	msgs = append(msgs, chatMessage{"user", prompt(state.User, state.Cwd, cmd)})

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()
	res, err := a.llm.Complete(ctx, msgs, 3000, false)
	if err != nil {
		return res, termReply{}, err
	}
	var out termReply
	if err := extractJSON(res.Content, &out); err != nil {
		out = termReply{Output: strings.TrimSpace(res.Content), Cwd: state.Cwd, User: state.User}
	}
	out.Output = strings.TrimRight(out.Output, "\n")
	return res, out, nil
}
