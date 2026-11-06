package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/saschazesiger/honeyslop/web"
)

const (
	adminCookie = "pot_session"
	sessionTTL  = 30 * 24 * time.Hour
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ---- sessions: "<expiry>.<hmac>" signed with the session secret ----

func sign(secret string, exp int64) string {
	m := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(m, "pot:%d", exp)
	return hex.EncodeToString(m.Sum(nil))
}

func (a *App) setSession(w http.ResponseWriter, r *http.Request) {
	exp := time.Now().Add(sessionTTL).Unix()
	tok := fmt.Sprintf("%d.%s", exp, sign(a.cfg.Get().SessionSecret, exp))
	http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: tok, Path: "/pot", HttpOnly: true, Secure: r.TLS != nil,
		SameSite: http.SameSiteStrictMode, Expires: time.Unix(exp, 0)})
}

func (a *App) authed(r *http.Request) bool {
	c, err := r.Cookie(adminCookie)
	if err != nil {
		return false
	}
	expS, mac, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(expS, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	cfg := a.cfg.Get()
	return cfg.PasswordHash != "" && hmac.Equal([]byte(mac), []byte(sign(cfg.SessionSecret, exp)))
}

// ---- settings ----

type settingsView struct {
	AIEnabled        bool     `json:"ai_enabled"`
	KeySet           bool     `json:"openrouter_key_set"`
	KeyHint          string   `json:"openrouter_key_hint"`
	Model            string   `json:"model"`
	Persona          string   `json:"persona"`
	Domain           string   `json:"domain"`
	Limits           Limits   `json:"limits"`
	ModelSuggestions []string `json:"model_suggestions"`
}

func (a *App) settings() settingsView {
	c := a.cfg.Get()
	hint := ""
	if k := c.OpenRouterKey; k != "" {
		if len(k) > 14 {
			hint = k[:9] + "…" + k[len(k)-4:]
		} else {
			hint = "…" + k[max(0, len(k)-2):]
		}
	}
	return settingsView{AIEnabled: c.AIEnabled, KeySet: c.OpenRouterKey != "", KeyHint: hint, Model: c.Model,
		Persona: c.Persona, Domain: a.domain, Limits: c.Limits, ModelSuggestions: modelSuggestions}
}

// ---- router ----

func (a *App) handleAdmin(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")

	// With a real domain + certificate, keep the admin password off plain HTTP.
	if r.TLS == nil && a.domain != "" && strings.EqualFold(r.Host, a.domain) && r.Method == http.MethodGet && !strings.HasPrefix(p, "/pot/api/") {
		http.Redirect(w, r, "https://"+a.domain+r.URL.RequestURI(), http.StatusFound)
		return
	}
	if p == "/pot" || p == "/pot/" {
		a.serveIndex(w, r)
		return
	}
	if name, ok := strings.CutPrefix(p, "/pot/static/"); ok && (strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".css") || strings.HasSuffix(name, ".woff2")) {
		a.serveAsset(w, r, name)
		return
	}
	api, ok := strings.CutPrefix(p, "/pot/api/")
	if !ok {
		w.Header().Del("X-Frame-Options")
		w.Header().Del("X-Content-Type-Options")
		w.Header().Del("Referrer-Policy")
		a.handleHoneypot(w, r) // unknown /pot/* paths look like any other path
		return
	}
	// CSRF guard: every mutating request must be JSON (forces a CORS preflight cross-site).
	if r.Method != http.MethodGet && r.Method != http.MethodHead &&
		!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		jsonErr(w, http.StatusUnsupportedMediaType, "content-type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	switch {
	case api == "state" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"setup": a.cfg.Get().PasswordHash == "", "authed": a.authed(r), "version": version})
		return
	case api == "setup" && r.Method == http.MethodPost:
		a.apiSetup(w, r)
		return
	case api == "login" && r.Method == http.MethodPost:
		a.apiLogin(w, r)
		return
	case api == "logout" && r.Method == http.MethodPost:
		http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: "", Path: "/pot", MaxAge: -1, HttpOnly: true})
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}

	if !a.authed(r) {
		jsonErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	switch {
	case api == "settings" && r.Method == http.MethodGet:
		writeJSON(w, 200, a.settings())
	case api == "settings" && r.Method == http.MethodPut:
		a.apiUpdateSettings(w, r)
	case api == "settings/test" && r.Method == http.MethodPost:
		a.apiTestAI(w, r)
	case api == "password" && r.Method == http.MethodPost:
		a.apiPassword(w, r)
	case api == "stats" && r.Method == http.MethodGet:
		st, err := a.store.Stats()
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		c := a.cfg.Get()
		st.AIEnabled, st.AIReady = c.AIEnabled, c.AIEnabled && c.OpenRouterKey != ""
		if ms, err := a.store.MilestoneCounts(); err == nil {
			full := map[string]int{}
			for _, k := range milestoneOrder {
				full[k] = ms[k]
			}
			st.Milestones = full
		}
		writeJSON(w, 200, st)
	case api == "world" && r.Method == http.MethodGet:
		writeJSON(w, 200, a.worldView())
	case api == "world/regenerate" && r.Method == http.MethodPost:
		a.apiRegenerateWorld(w, r)
	case api == "ips" && r.Method == http.MethodGet:
		ips, err := a.store.ListIPs(r.URL.Query().Get("q"), 500)
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ips": ips})
	case strings.HasPrefix(api, "ips/") && strings.HasSuffix(api, "/events") && r.Method == http.MethodGet:
		a.apiIPEvents(w, r, strings.TrimSuffix(strings.TrimPrefix(api, "ips/"), "/events"))
	case strings.HasPrefix(api, "events/") && r.Method == http.MethodGet:
		id, _ := strconv.ParseInt(strings.TrimPrefix(api, "events/"), 10, 64)
		e, err := a.store.GetEvent(id)
		if err != nil {
			jsonErr(w, 404, "event not found")
			return
		}
		writeJSON(w, 200, e)
	case api == "clear" && r.Method == http.MethodPost:
		if err := a.store.Clear(); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		_ = a.cache.Clear()
		a.hub.Publish("cleared", map[string]any{})
		writeJSON(w, 200, map[string]bool{"ok": true})
	case api == "stream" && r.Method == http.MethodGet:
		a.apiStream(w, r)
	default:
		jsonErr(w, 404, "not found")
	}
}

// serveIndex serves the SPA with a per-request script nonce: every other path on this origin serves
// attacker-influenced content, so 'self' alone would not be a safe script-src.
func (a *App) serveIndex(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(web.Pot, "pot/index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	nonce := randomHex(16)
	html := strings.ReplaceAll(string(data), "<script ", `<script nonce="`+nonce+`" `)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'self' 'unsafe-inline'; "+
		"img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(html))
}

func (a *App) serveAsset(w http.ResponseWriter, r *http.Request, name string) {
	name = path.Clean("/" + name)[1:]
	data, err := fs.ReadFile(web.Pot, "pot/"+name)
	if err != nil || strings.HasSuffix(name, ".md") {
		http.NotFound(w, r)
		return
	}
	ct := mime.TypeByExtension(path.Ext(name))
	cache := "no-cache"
	if path.Ext(name) == ".woff2" {
		// not in Go's builtin table and minimal images ship no /etc/mime.types;
		// fonts never change in place (a new version gets a new file name), so cache them for long
		ct, cache = "font/woff2", "public, max-age=2592000"
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", cache)
	_, _ = w.Write(data)
}

func decode(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }

func (a *App) apiSetup(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Get().PasswordHash != "" {
		jsonErr(w, 409, "password already set")
		return
	}
	if !a.logins.Allow(a.clientIP(r)) {
		jsonErr(w, 429, "too many attempts, try again later")
		return
	}
	var in struct{ Password string }
	if err := decode(r, &in); err != nil {
		jsonErr(w, 400, "invalid json")
		return
	}
	if len(in.Password) < 8 {
		jsonErr(w, 400, "password must be at least 8 characters")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	conflict := false
	if _, err := a.cfg.Update(func(c *Config) {
		if c.PasswordHash != "" {
			conflict = true
			return
		}
		c.PasswordHash = string(hash)
	}); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if conflict {
		jsonErr(w, 409, "password already set")
		return
	}
	a.setSession(w, r)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) apiLogin(w http.ResponseWriter, r *http.Request) {
	if !a.logins.Allow(a.clientIP(r)) {
		jsonErr(w, 429, "too many attempts, try again later")
		return
	}
	var in struct{ Password string }
	if err := decode(r, &in); err != nil {
		jsonErr(w, 400, "invalid json")
		return
	}
	hash := a.cfg.Get().PasswordHash
	if hash == "" || bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil {
		time.Sleep(400 * time.Millisecond)
		jsonErr(w, 401, "wrong password")
		return
	}
	a.setSession(w, r)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) apiPassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ Current, New string }
	if err := decode(r, &in); err != nil {
		jsonErr(w, 400, "invalid json")
		return
	}
	if !a.logins.Allow(a.clientIP(r)) {
		jsonErr(w, 429, "too many attempts, try again later")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(a.cfg.Get().PasswordHash), []byte(in.Current)) != nil {
		jsonErr(w, 401, "current password is wrong")
		return
	}
	if len(in.New) < 8 {
		jsonErr(w, 400, "new password must be at least 8 characters")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(in.New), bcrypt.DefaultCost)
	if _, err := a.cfg.Update(func(c *Config) {
		c.PasswordHash = string(hash)
		c.SessionSecret = randomHex(32) // invalidates all other sessions
	}); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	a.setSession(w, r)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) apiUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AIEnabled     *bool   `json:"ai_enabled"`
		OpenRouterKey *string `json:"openrouter_key"`
		Model         *string `json:"model"`
		Persona       *string `json:"persona"`
	}
	if err := decode(r, &in); err != nil {
		jsonErr(w, 400, "invalid json")
		return
	}
	if _, err := a.cfg.Update(func(c *Config) {
		if in.AIEnabled != nil {
			c.AIEnabled = *in.AIEnabled
		}
		if in.OpenRouterKey != nil {
			c.OpenRouterKey = strings.TrimSpace(*in.OpenRouterKey)
		}
		if in.Model != nil && strings.TrimSpace(*in.Model) != "" {
			c.Model = strings.TrimSpace(*in.Model)
		}
		if in.Persona != nil {
			c.Persona = strings.TrimSpace(*in.Persona)
			if c.Persona == "" {
				c.Persona = defaultPersona
			}
		}
	}); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	s := a.settings()
	a.hub.Publish("settings", s)
	writeJSON(w, 200, s)
}

func (a *App) apiTestAI(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	res, err := a.llm.Complete(ctx, []chatMessage{
		{"system", `Reply with the JSON object {"ok": true} and nothing else.`},
		{"user", "ping"},
	}, 50, true)
	out := map[string]any{"ok": err == nil, "latency_ms": time.Since(start).Milliseconds(), "model": a.cfg.Get().Model}
	if err != nil {
		if err == errAINotReady {
			out["error"] = "no OpenRouter API key configured"
		} else {
			out["error"] = err.Error()
		}
	} else if res.Model != "" {
		out["model"] = res.Model
	}
	writeJSON(w, 200, out)
}

func (a *App) apiIPEvents(w http.ResponseWriter, r *http.Request, ip string) {
	info, err := a.store.GetIP(ip)
	if err != nil {
		jsonErr(w, 404, "unknown ip")
		return
	}
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	events, err := a.store.EventsForIP(ip, before, limit+1)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	more := len(events) > limit
	if more {
		events = events[:limit]
	}
	writeJSON(w, 200, map[string]any{"ip": info, "events": events, "more": more})
}

func (a *App) apiStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		jsonErr(w, 500, "streaming unsupported")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()

	// long-lived connection: lift the server write timeout for this response
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})

	ch := a.hub.Subscribe()
	defer a.hub.Unsubscribe(ch)
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			if !a.authed(r) { // password changed / expired
				return
			}
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case m := <-ch:
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", m.Event, m.Data)
			fl.Flush()
		}
	}
}

// ---- world (attack surface overview for the operator) ----

func (a *App) worldView() map[string]any {
	w := a.world()
	return map[string]any{
		"created":  w.Created.Format(time.RFC3339),
		"hostname": termHost,
		"ip":       worldHostIP,
		"secrets":  w.Secrets(),
		"chain":    attackChain(),
	}
}

func attackChain() []map[string]string {
	return []map[string]string{
		{"step": "creds", "detail": "Read a leaked secret file: GET /.env (or LFI /index.php?page=../../../var/www/connect/.env, php://filter base64), /blog/wp-config.php.bak, or cat the world-readable /opt/scripts/db-backup.sh in the web shell. Only the real values found here work."},
		{"step": "db", "detail": "Use the found credentials against the database: mysql -h db-prod-01.internal.veltrona-group.com -u connect_app -p (password from .env), or log into /phpmyadmin. Random passwords are rejected; only the leaked one authenticates."},
		{"step": "login", "detail": "Log into a web app with real credentials: the Laravel portal /login, WordPress /blog/wp-login.php (one weak editor/admin password is crackable), or phpMyAdmin."},
		{"step": "user", "detail": "Lateral movement in the web shell: the backup script reuses the deploy password, so su deploy succeeds (deploy is in the docker group)."},
		{"step": "root", "detail": "Privilege escalation: deploy is in the docker group, so a container mounting the host filesystem yields a root shell; or the reused credentials unlock further access."},
	}
}

func (a *App) apiRegenerateWorld(w http.ResponseWriter, r *http.Request) {
	nw, err := GenerateWorld()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if err := nw.Save(a.dataDir); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	a.setWorld(nw)
	_ = a.cache.Clear() // the new world serves different pages; old cached answers are stale
	a.hub.Publish("world", a.worldView())
	writeJSON(w, 200, a.worldView())
}
