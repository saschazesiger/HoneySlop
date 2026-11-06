package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	serverHeader   = "nginx/1.18.0 (Ubuntu)"
	maxBodyRead    = 1 << 20  // read at most 1 MB of request body
	maxBodyStore   = 64 << 10 // store at most 64 KB per body
	maxBodyForLLM  = 8 << 10  // send at most 8 KB of body to the LLM
	historyForHTTP = 6        // previous AI exchanges of the same IP given to the LLM
)

// Scripts in AI generated pages run in an opaque origin, so reflected "XSS" still pops
// for the attacker but can never reach the /pot admin API on the same host.
const sandboxCSP = "sandbox allow-scripts allow-forms allow-popups allow-modals allow-downloads"

func nginxPage(code int, text string) string {
	return fmt.Sprintf("<html>\r\n<head><title>%d %s</title></head>\r\n<body>\r\n<center><h1>%d %s</h1></center>\r\n<hr><center>%s</center>\r\n</body>\r\n</html>\r\n",
		code, text, code, text, serverHeader)
}

// static (non-AI) answers for assets the LLM can't meaningfully produce
var binaryExt = map[string]bool{
	".ico": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".svg": true, ".bmp": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true, ".mp4": true, ".mp3": true, ".webm": true,
	".avi": true, ".mov": true, ".pdf": true, ".exe": true, ".dll": true, ".so": true, ".apk": true,
}

func (a *App) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	// Only trust forwarding headers when the direct peer is a private proxy (e.g. your own nginx).
	if a.cfg.Get().TrustProxy && isPrivateIP(host) {
		if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(v) != nil {
			return v
		}
		if parts := strings.Split(r.Header.Get("X-Forwarded-For"), ","); len(parts) > 0 {
			if v := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(v) != nil { // rightmost = added by our proxy
				return v
			}
		}
	}
	return host
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func readBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, maxBodyRead))
	return string(b)
}

// newEvent fills the request side of an event.
func (a *App) newEvent(r *http.Request, kind, body string) *Event {
	return &Event{
		TS:         time.Now().UnixMilli(),
		IP:         a.clientIP(r),
		Kind:       kind,
		Method:     r.Method,
		Scheme:     scheme(r),
		Host:       r.Host,
		Path:       r.URL.RequestURI(),
		Proto:      r.Proto,
		ReqHeaders: r.Header.Clone(),
		ReqBody:    truncate(body, maxBodyStore),
		UserAgent:  r.UserAgent(),
	}
}

// record persists an event and notifies dashboards.
func (a *App) record(e *Event) {
	e.RespBody = truncate(e.RespBody, maxBodyStore)
	info, isNew, err := a.store.InsertEvent(e)
	if err != nil {
		log.Printf("db: insert event: %v", err)
		return
	}
	if isNew || info.Geo == "pending" {
		a.geo.Resolve(e.IP)
	}
	a.hub.Publish("hit", map[string]any{"ip": info, "event": e.Summary()})
}

func rawRequest(r *http.Request, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto)
	fmt.Fprintf(&b, "Host: %s\r\n", r.Host)
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range r.Header[k] {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	if len(body) > maxBodyForLLM {
		body = body[:maxBodyForLLM] + "\n[... truncated]"
	}
	b.WriteString(body)
	return b.String()
}

type httpReply struct {
	Status  int            `json:"status"`
	Headers map[string]any `json:"headers"`
	Body    string         `json:"body"`
	hdr     map[string]string
}

// handleHoneypot answers every path except / and /pot.
func (a *App) handleHoneypot(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	ev := a.newEvent(r, "http", body)
	start := time.Now()

	status := http.StatusNotFound
	headers := map[string]string{"Content-Type": "text/html"}
	respBody := nginxPage(404, "Not Found")

	ext := strings.ToLower(path.Ext(r.URL.Path))
	cfg := a.cfg.Get()
	switch {
	case binaryExt[ext]:
		ev.Source = "static"
	case !cfg.AIEnabled || cfg.OpenRouterKey == "":
		ev.Source = "disabled"
	default:
		if !a.limiter.Allow(ev.IP) {
			ev.Source = "ratelimited"
			break
		}
		reply, res, err := a.generateHTTP(r.Context(), r, body, ev.IP)
		if err != nil {
			log.Printf("llm http %s %s: %v", ev.IP, ev.Path, err)
			ev.Source = "error"
			status, respBody = http.StatusBadGateway, nginxPage(502, "Bad Gateway")
			break
		}
		ev.Source, ev.Model, ev.Tokens = "ai", res.Model, res.Tokens
		status, headers, respBody = reply.Status, reply.hdr, reply.Body
	}

	h := w.Header()
	for k, v := range headers {
		h.Set(k, v)
	}
	h.Set("Server", serverHeader)
	if ev.Source == "ai" {
		h.Set("Content-Security-Policy", sandboxCSP)
	}
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, respBody)
	}

	ev.Status = status
	ev.RespHeaders = h.Clone()
	ev.RespBody = respBody
	ev.LatencyMS = time.Since(start).Milliseconds()
	a.record(ev)
}

// headers the model must not control
var blockedRespHeaders = map[string]bool{
	"content-length": true, "transfer-encoding": true, "connection": true, "content-encoding": true,
	"server": true, "content-security-policy": true, "strict-transport-security": true, "date": true,
	"keep-alive": true, "upgrade": true, "trailer": true, "alt-svc": true, "clear-site-data": true,
	"access-control-allow-origin": true, "access-control-allow-credentials": true,
}

func (a *App) generateHTTP(ctx context.Context, r *http.Request, body, ip string) (httpReply, llmResult, error) {
	cfg := a.cfg.Get()
	sys := strings.NewReplacer("{{PERSONA}}", cfg.Persona, "{{HOST}}", r.Host).Replace(httpSystemPrompt)

	var u strings.Builder
	if prev, err := a.store.RecentHTTPForIP(ip, historyForHTTP); err == nil && len(prev) > 0 {
		u.WriteString("PREVIOUS RESPONSES THIS SERVER ALREADY SENT TO THE SAME CLIENT (stay consistent with them):\n")
		for _, p := range prev {
			fmt.Fprintf(&u, "\n--- %s %s → %d (%s)\n%s\n", p.Method, truncate(p.Path, 300), p.Status,
				p.RespHeaders.Get("Content-Type"), truncate(p.RespBody, 1500))
		}
		u.WriteString("\n=====\n\n")
	}
	fmt.Fprintf(&u, "CURRENT RAW HTTP REQUEST (received at %s):\n\n%s", time.Now().UTC().Format(time.RFC1123), rawRequest(r, body))

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()
	res, err := a.llm.Complete(ctx, []chatMessage{{"system", sys}, {"user", u.String()}}, 6000, false)
	if err != nil {
		return httpReply{}, res, err
	}
	var rep httpReply
	if err := extractJSON(res.Content, &rep); err != nil || (rep.Body == "" && rep.Status == 0) {
		// model ignored the format: serve its text as an HTML page
		rep = httpReply{Status: 200, Body: res.Content}
	}
	if rep.Status < 200 || rep.Status > 599 {
		rep.Status = 200
	}
	rep.hdr = map[string]string{}
	for k, v := range rep.Headers {
		ck := http.CanonicalHeaderKey(strings.TrimSpace(k))
		if ck == "" || blockedRespHeaders[strings.ToLower(ck)] || strings.ContainsAny(ck, " \r\n:") {
			continue
		}
		sv := strings.NewReplacer("\r", "", "\n", "").Replace(fmt.Sprint(v))
		if ck == "Set-Cookie" && (strings.Contains(sv, adminCookie) || strings.Contains(strings.ToLower(sv), "path=/pot")) {
			continue // never let generated content touch the admin session
		}
		rep.hdr[ck] = sv
	}
	if rep.hdr["Content-Type"] == "" {
		rep.hdr["Content-Type"] = "text/html; charset=UTF-8"
	}
	return rep, res, nil
}
