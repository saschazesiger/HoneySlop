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

// TermState is the full state of a web-shell session, serialized between HTTP requests.
type TermState struct {
	Ctx     ShellCtx     `json:"ctx"`
	Stack   []ShellCtx   `json:"stack,omitempty"`   // parent shells (su / sudo -i chain)
	Pending *Pending     `json:"pending,omitempty"` // waiting for a hidden password line
	Mysql   *MySQLClient `json:"mysql,omitempty"`   // inside the interactive mysql monitor
}

func defaultTermState() TermState {
	return TermState{Ctx: ShellCtx{User: termDefaultUser, Cwd: termDefaultCwd, Env: map[string]string{}}}
}

// termLine is one rendered history row sent to the browser.
type termLine struct {
	Cmd    string `json:"cmd"`
	Output string `json:"output"`
	Cwd    string `json:"cwd"`
	User   string `json:"user"`
	Prompt string `json:"prompt,omitempty"` // "" shell, "mysql> ", "    -> ", "Password: " ...
	Hidden bool   `json:"hidden,omitempty"` // command was typed into a hidden password prompt
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

// loadTermState reconstructs the session state from the last stored terminal event.
func loadTermState(hist []Event) TermState {
	for i := len(hist) - 1; i >= 0; i-- {
		if hist[i].TermState != "" {
			var st TermState
			if err := json.Unmarshal([]byte(hist[i].TermState), &st); err == nil {
				if st.Ctx.Env == nil {
					st.Ctx.Env = map[string]string{}
				}
				if st.Ctx.User == "" {
					st.Ctx.User = termDefaultUser
				}
				if st.Ctx.Cwd == "" {
					st.Ctx.Cwd = termDefaultCwd
				}
				return st
			}
		}
	}
	return defaultTermState()
}

// nextPrompt reports the prompt the browser should show given the state after a command.
func nextPrompt(st TermState) (prompt string, hidden bool) {
	switch {
	case st.Pending != nil:
		return promptText(st.Pending), true
	case st.Mysql != nil:
		if st.Mysql.Buf != "" {
			return "    -> ", false // mid-statement continuation
		}
		return "mysql> ", false
	default:
		return "", false
	}
}

func promptText(p *Pending) string {
	switch p.Kind {
	case "sudo":
		if p.SudoPrompt != "" {
			return p.SudoPrompt
		}
		return "[sudo] password for " + p.User + ": "
	case "mysql", "mysqldump":
		return "Enter password: "
	default:
		return "Password: "
	}
}

func (a *App) handleTerminalPage(w http.ResponseWriter, r *http.Request) {
	sid := a.termSession(w, r)
	hist, _ := a.store.TerminalHistory(sid, maxHistoryCmds)
	st := loadTermState(hist)
	lines := make([]termLine, 0, len(hist))
	for _, e := range hist {
		prompt, hidden := renderHistoryPrompt(e.Prompt)
		lines = append(lines, termLine{Cmd: e.Cmd, Output: e.RespBody, Cwd: e.Cwd, User: termUserOr(e.TermUser),
			Prompt: prompt, Hidden: hidden})
	}
	prompt, hidden := nextPrompt(st)
	boot, _ := json.Marshal(map[string]any{
		"host": termHost, "cwd": st.Ctx.Cwd, "user": st.Ctx.User, "history": lines, "motd": motd(),
		"prompt": prompt, "hidden": hidden,
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

func termUserOr(u string) string {
	if u == "" {
		return termDefaultUser
	}
	return u
}

// renderHistoryPrompt maps a stored input-prompt string to what the browser should show for that line.
func renderHistoryPrompt(stored string) (prompt string, hidden bool) {
	switch {
	case isSQLPrompt(stored):
		return "mysql> ", false
	case isPasswordPrompt(stored):
		return stored, true // password line: prompt shown, input masked
	default:
		return "", false
	}
}

func isPasswordPrompt(s string) bool { return strings.Contains(strings.ToLower(s), "pass") }

func isSQLPrompt(s string) bool {
	t := strings.TrimSpace(s)
	return t == "mysql>" || t == "->" || t == "mysql> " || t == "    ->"
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

// handleTerminalCommand executes one line of the fake shell (POST / with JSON).
func (a *App) handleTerminalCommand(w http.ResponseWriter, r *http.Request, body string) {
	var in struct {
		Cmd string `json:"cmd"`
	}
	_ = json.Unmarshal([]byte(body), &in)
	cmd := strings.TrimSpace(truncate(in.Cmd, 8000))
	sid := a.termSession(w, r)
	start := time.Now()

	hist, _ := a.store.TerminalHistory(sid, maxHistoryCmds)
	st := loadTermState(hist)
	st.Ctx.SID = sid

	// store only the command, not padding; mask nothing server-side (operator wants to see attempts)
	reqBody, _ := json.Marshal(map[string]string{"cmd": in.Cmd})
	ev := a.newEvent(r, "terminal", string(reqBody))
	ev.Method, ev.Path, ev.Cmd, ev.Cwd, ev.Session = "SHELL", "/", cmd, st.Ctx.Cwd, sid
	ev.TermUser = st.Ctx.User

	cfg := a.cfg.Get()
	// input mode of THIS line (before dispatch): password continuation, sql monitor or normal shell
	inPrompt := ""
	if st.Pending != nil {
		inPrompt = promptText(st.Pending)
	} else if st.Mysql != nil {
		inPrompt = "mysql>"
	}
	res, llmNeeded := a.dispatchTerminal(r.Context(), &st, cmd, hist, cfg)
	if llmNeeded {
		if !cfg.AIEnabled || cfg.OpenRouterKey == "" {
			res.Output = "-bash: fork: retry: Resource temporarily unavailable"
			ev.Source = "disabled"
		} else if !a.limiter.Allow(ev.IP) {
			res.Output = "-bash: fork: retry: Resource temporarily unavailable"
			ev.Source = "ratelimited"
		} else {
			lres, out, err := a.generateTerminal(r.Context(), hist, st.Ctx, cmd, res.Facts)
			if err != nil {
				log.Printf("llm terminal %s: %v", ev.IP, err)
				res.Output, ev.Source = "-bash: fork: Cannot allocate memory", "error"
			} else {
				res.Output = out.Output
				ev.Model, ev.Tokens, ev.Source = lres.Model, lres.Tokens, "ai"
				// the LLM may move the working directory, but it can NEVER change the user (privilege is enforced in Go)
				if strings.HasPrefix(out.Cwd, "/") {
					st.Ctx.Cwd = out.Cwd
				}
			}
		}
	} else {
		ev.Source = "static"
	}

	// milestones reached by this command (label the event now; persist the aggregate after record)
	var newly []string
	if len(res.Flags) > 0 {
		newly = a.store.PreviewMilestones(ev.IP, res.Flags)
	}
	ev.Flags = strings.Join(newly, ",")

	// response prompt describes the NEXT line; the stored ev.Prompt describes THIS line's input mode
	prompt, promptHidden := nextPrompt(st)
	ev.Prompt = inPrompt
	stJSON, _ := json.Marshal(st)
	ev.TermState = string(stJSON)

	resp := map[string]any{
		"output": res.Output, "cwd": st.Ctx.Cwd, "user": st.Ctx.User,
		"prompt": prompt, "hidden": promptHidden,
	}
	if len(newly) > 0 {
		resp["flags"] = newly
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", serverHeader)
	_ = json.NewEncoder(w).Encode(resp)

	ev.Status = 200
	ev.RespBody = res.Output
	ev.LatencyMS = time.Since(start).Milliseconds()
	a.record(ev)
}

// dispatchTerminal routes one line to the right handler and mutates st in place.
// Returns the result and whether the LLM must still produce the output.
func (a *App) dispatchTerminal(ctx context.Context, st *TermState, cmd string, hist []Event, cfg Config) (ShellResult, bool) {
	// 1. a hidden password / continuation line
	if st.Pending != nil {
		p := st.Pending
		st.Pending = nil
		res := a.shell().Continue(ctx, &st.Ctx, p, cmd)
		a.applyShellResult(st, res)
		return res, false
	}
	// 2. inside the interactive mysql monitor
	if st.Mysql != nil {
		out, next, _ := a.mysql().Line(ctx, st.Ctx.SID, *st.Mysql, cmd)
		res := ShellResult{Cwd: st.Ctx.Cwd, User: st.Ctx.User, Handled: true, Output: out}
		st.Mysql = next
		return res, false
	}
	// 3. exit/logout pops a nested shell (su / sudo -i) before anything else
	if t := strings.TrimSpace(cmd); (t == "exit" || t == "logout" || t == "exit;") && len(st.Stack) > 0 {
		parent := st.Stack[len(st.Stack)-1]
		st.Stack = st.Stack[:len(st.Stack)-1]
		st.Ctx.User, st.Ctx.Cwd, st.Ctx.Env = parent.User, parent.Cwd, parent.Env
		return ShellResult{Cwd: st.Ctx.Cwd, User: st.Ctx.User, Handled: true, Output: ""}, false
	}
	// 4. normal command
	res := a.shell().Run(ctx, &st.Ctx, cmd)
	a.applyShellResult(st, res)
	if res.Handled {
		return res, false
	}
	return res, true
}

// applyShellResult folds a ShellResult into the session state (user switches push/pop the shell stack).
func (a *App) applyShellResult(st *TermState, res ShellResult) {
	if res.Interact != nil && res.Interact.Mysql != nil {
		st.Mysql = res.Interact.Mysql
	}
	if res.Pending != nil {
		st.Pending = res.Pending
		if res.Prompt != "" && res.Pending.Kind == "sudo" {
			st.Pending.SudoPrompt = res.Prompt
		}
	}
	if res.User != "" && res.User != st.Ctx.User {
		// privilege change: remember the parent shell so `exit` returns to it
		parent := st.Ctx
		st.Stack = append(st.Stack, parent)
		st.Ctx.User = res.User
		st.Ctx.Cwd = res.Cwd
		st.Ctx.Env = map[string]string{}
	} else if res.Cwd != "" {
		st.Ctx.Cwd = res.Cwd
	}
}

type termReply struct {
	Output string `json:"output"`
	Cwd    string `json:"cwd"`
	User   string `json:"user"`
}

func (a *App) generateTerminal(ctx context.Context, hist []Event, ctxState ShellCtx, cmd, facts string) (llmResult, termReply, error) {
	cfg := a.cfg.Get()
	sys := strings.NewReplacer("{{PERSONA}}", cfg.Persona, "{{DATE}}", time.Now().UTC().Format("Mon Jan 2 15:04:05 UTC 2006")).
		Replace(terminalSystemPrompt) + facts

	prompt := func(user, cwd, c string) string {
		return fmt.Sprintf("[user=%s cwd=%s]\n$ %s", user, cwd, c)
	}
	var turns []chatMessage
	for _, e := range hist {
		if e.Cmd == "" || isPasswordPrompt(e.Prompt) {
			continue
		}
		reply, _ := json.Marshal(termReply{Output: e.RespBody, Cwd: e.Cwd, User: termUserOr(e.TermUser)})
		turns = append(turns, chatMessage{"user", prompt(termUserOr(e.TermUser), e.Cwd, e.Cmd)}, chatMessage{"assistant", string(reply)})
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
	msgs = append(msgs, chatMessage{"user", prompt(ctxState.User, ctxState.Cwd, cmd)})

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()
	res, err := a.llm.Complete(ctx, msgs, 3000, false)
	if err != nil {
		return res, termReply{}, err
	}
	var out termReply
	if err := extractJSON(res.Content, &out); err != nil {
		out = termReply{Output: strings.TrimSpace(res.Content), Cwd: ctxState.Cwd, User: ctxState.User}
	}
	out.Output = strings.TrimRight(out.Output, "\n")
	return res, out, nil
}
