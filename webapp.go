package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// WebApp answers the HTTP paths whose outcome must be deterministic and consistent with the world:
// leaking real secret files (so the credentials found match the ones that actually work), and the
// login realms (where only real credentials succeed, enforcing a real challenge). Everything else
// still falls through to the LLM.
type WebApp struct {
	app   *App
	world *World
}

func NewWebApp(a *App, w *World) *WebApp { return &WebApp{app: a, world: w} }

type webReply struct {
	status  int
	headers map[string]string
	body    string
}

func htmlReply(status int, body string) *webReply {
	return &webReply{status: status, headers: map[string]string{"Content-Type": "text/html; charset=UTF-8"}, body: body}
}

// Handle tries to answer a request deterministically. ok=false → let the LLM answer.
// flags are milestones reached by this request.
func (wa *WebApp) Handle(r *http.Request, body string) (reply *webReply, flags []string, ok bool) {
	p := r.URL.Path
	low := strings.ToLower(p)

	// 1. file leaks: direct sensitive paths and LFI/traversal parameters
	if reply, flags, ok = wa.tryFileLeak(r); ok {
		return reply, flags, true
	}

	// 2. login realms (GET renders the form, POST checks real credentials)
	switch {
	case low == "/blog/wp-login.php" || low == "/wp-login.php":
		return wa.wpLogin(r, body)
	case strings.HasPrefix(low, "/phpmyadmin") && (low == "/phpmyadmin/" || low == "/phpmyadmin" || low == "/phpmyadmin/index.php"):
		return wa.phpMyAdmin(r, body)
	case low == "/login" || low == "/api/login" || low == "/api/auth/login" || low == "/connect/login":
		return wa.portalLogin(r, body)
	}
	return nil, nil, false
}

// ---------- file leaks ----------

// sensitiveWebPaths maps request paths (as an attacker would hit them) to the VFS file that leaks.
func (wa *WebApp) sensitiveWebPaths() map[string]string {
	return map[string]string{
		"/.env":                    "/var/www/connect/.env",
		"/connect/.env":            "/var/www/connect/.env",
		"/.env.bak":                "/var/www/connect/.env",
		"/.env.save":               "/var/www/connect/.env",
		"/.env.example":            "/var/www/connect/.env.example",
		"/blog/wp-config.php.bak":  "/var/www/blog/wp-config.php",
		"/blog/wp-config.php~":     "/var/www/blog/wp-config.php",
		"/wp-config.php.bak":       "/var/www/blog/wp-config.php",
		"/blog/wp-config.php.save": "/var/www/blog/wp-config.php",
		"/composer.json":           "/var/www/connect/composer.json",
		"/connect/composer.json":   "/var/www/connect/composer.json",
	}
}

func (wa *WebApp) tryFileLeak(r *http.Request) (*webReply, []string, bool) {
	// (a) direct sensitive path
	if vp, ok := wa.sensitiveWebPaths()[strings.ToLower(r.URL.Path)]; ok {
		if f := wa.world.Lookup(vp); f != nil {
			return wa.leakFile(f, false), wa.leakFlags(f), true
		}
	}
	// (b) LFI / path traversal through common parameters
	params := []string{"file", "page", "path", "doc", "document", "template", "include", "view", "load", "f", "name", "filename", "download"}
	q := r.URL.Query()
	for _, key := range params {
		raw := q.Get(key)
		if raw == "" {
			continue
		}
		if vp, b64, ok := wa.resolveLFI(raw); ok {
			if f := wa.world.Lookup(vp); f != nil && !f.Dir {
				if wa.world.AccessError(termDefaultUser, vp, "r") != "" {
					continue // www-data can't read it: not a successful leak, let the LLM 404/deny
				}
				return wa.leakFile(f, b64), wa.leakFlags(f), true
			}
			if vp == "/etc/passwd" || vp == "/etc/hosts" || vp == "/etc/hostname" || vp == "/proc/version" {
				if f := wa.world.Lookup(vp); f != nil {
					return wa.leakFile(f, b64), nil, true
				}
			}
		}
	}
	return nil, nil, false
}

// resolveLFI normalizes an LFI payload to an absolute VFS path. b64 = wrapped in php://filter base64.
func (wa *WebApp) resolveLFI(raw string) (vpath string, b64 bool, ok bool) {
	s := raw
	if dec, err := url.QueryUnescape(s); err == nil {
		s = dec
	}
	s = strings.TrimSpace(strings.ReplaceAll(s, "\x00", "")) // null-byte trick
	// php://filter/convert.base64-encode/resource=...
	if i := strings.Index(strings.ToLower(s), "php://filter"); i >= 0 {
		b64 = strings.Contains(strings.ToLower(s), "base64")
		if j := strings.LastIndex(strings.ToLower(s), "resource="); j >= 0 {
			s = s[j+len("resource="):]
		} else {
			return "", false, false
		}
	}
	if strings.HasPrefix(strings.ToLower(s), "file://") {
		s = s[len("file://"):]
	}
	if !strings.Contains(s, "..") && !strings.HasPrefix(s, "/") {
		return "", false, false // ordinary relative asset, not an obvious traversal
	}
	// resolve relative to the app public root, honoring ../
	start := s
	if !strings.HasPrefix(s, "/") {
		start = path.Join(termDefaultCwd, s)
	}
	clean := path.Clean(start)
	if !strings.HasPrefix(clean, "/") {
		return "", false, false
	}
	return clean, b64, true
}

func (wa *WebApp) leakFile(f *VFile, b64 bool) *webReply {
	body := f.Content
	ct := "text/plain; charset=UTF-8"
	if b64 {
		body = base64.StdEncoding.EncodeToString([]byte(f.Content))
	}
	return &webReply{status: 200, headers: map[string]string{"Content-Type": ct}, body: body}
}

func (wa *WebApp) leakFlags(f *VFile) []string {
	if wa.world.LeaksSecret(f.Content) {
		return []string{msCreds}
	}
	return nil
}

// ---------- login realms ----------

func formValues(r *http.Request, body string) url.Values {
	v, _ := url.ParseQuery(body)
	if len(v) == 0 && r.URL.RawQuery != "" {
		v = r.URL.Query()
	}
	return v
}

func (wa *WebApp) wpLogin(r *http.Request, body string) (*webReply, []string, bool) {
	if r.Method != http.MethodPost {
		return htmlReply(200, wpLoginPage("")), nil, true
	}
	v := formValues(r, body)
	login, pass := v.Get("log"), v.Get("pwd")
	if login == "" && pass == "" {
		return htmlReply(200, wpLoginPage("")), nil, true
	}
	u := wa.world.WPUserByLogin(login)
	if u == nil || u.Password != pass {
		msg := `<strong>Error:</strong> The password you entered for the username <strong>` + htmlEscape(login) + `</strong> is incorrect.`
		if u == nil {
			msg = `<strong>Error:</strong> The username <strong>` + htmlEscape(login) + `</strong> is not registered on this site.`
		}
		return &webReply{status: 200, headers: map[string]string{"Content-Type": "text/html; charset=UTF-8"}, body: wpLoginPage(msg)}, nil, true
	}
	// success: set the WordPress auth cookies and redirect to the dashboard
	cookie := fmt.Sprintf("wordpress_logged_in_%s=%s%%7C%d%%7C%s; path=/blog/; HttpOnly",
		rstrSeed(wa.world, 8), url.QueryEscape(u.Login), time.Now().Add(48*time.Hour).Unix(), rstrSeed(wa.world, 34))
	return &webReply{status: 302, headers: map[string]string{
		"Location":   "/blog/wp-admin/",
		"Set-Cookie": cookie,
	}, body: ""}, []string{msLogin}, true
}

func (wa *WebApp) portalLogin(r *http.Request, body string) (*webReply, []string, bool) {
	if r.Method != http.MethodPost {
		return htmlReply(200, portalLoginPage("")), nil, true
	}
	v := formValues(r, body)
	email := firstNonEmpty(v.Get("email"), v.Get("username"), v.Get("user"), v.Get("login"))
	pass := firstNonEmpty(v.Get("password"), v.Get("pass"), v.Get("passwd"))
	// JSON bodies (API login)
	if email == "" && strings.Contains(r.Header.Get("Content-Type"), "json") {
		email, pass = jsonField(body, "email"), jsonField(body, "password")
		if email == "" {
			email = jsonField(body, "username")
		}
	}
	isAPI := strings.HasPrefix(strings.ToLower(r.URL.Path), "/api/") || strings.Contains(r.Header.Get("Accept"), "json")
	u := wa.world.AppUserByEmail(email)
	if u == nil || u.Password != pass {
		if isAPI {
			return &webReply{status: 422, headers: map[string]string{"Content-Type": "application/json"},
				body: `{"message":"These credentials do not match our records.","errors":{"email":["These credentials do not match our records."]}}`}, nil, true
		}
		return htmlReply(422, portalLoginPage("These credentials do not match our records.")), nil, true
	}
	if isAPI {
		tok := fmt.Sprintf("%d|%s", u.ID, rstrSeed(wa.world, 40))
		return &webReply{status: 200, headers: map[string]string{"Content-Type": "application/json"},
			body: fmt.Sprintf(`{"token":%q,"user":{"id":%d,"name":%q,"email":%q,"role":%q}}`, tok, u.ID, u.Name, u.Email, u.Role)}, []string{msLogin}, true
	}
	sess := fmt.Sprintf("connect_session=%s; path=/; HttpOnly; SameSite=Lax", rstrSeed(wa.world, 40))
	return &webReply{status: 302, headers: map[string]string{"Location": "/dashboard", "Set-Cookie": sess}, body: ""}, []string{msLogin}, true
}

func (wa *WebApp) phpMyAdmin(r *http.Request, body string) (*webReply, []string, bool) {
	if r.Method != http.MethodPost {
		return htmlReply(200, phpMyAdminPage("")), nil, true
	}
	v := formValues(r, body)
	user, pass := v.Get("pma_username"), v.Get("pma_password")
	if user == "" {
		return htmlReply(200, phpMyAdminPage("")), nil, true
	}
	if _, ok := wa.world.CheckMySQL(user, pass); !ok {
		return htmlReply(200, phpMyAdminPage("#1045 Cannot log in to the MySQL server")), nil, true
	}
	token := rstrSeed(wa.world, 32)
	return &webReply{status: 302, headers: map[string]string{
		"Location":   "/phpmyadmin/index.php?route=/&token=" + token,
		"Set-Cookie": "phpMyAdmin=" + rstrSeed(wa.world, 26) + "; path=/phpmyadmin/; HttpOnly",
	}, body: ""}, []string{msDB, msLogin}, true
}

// ---------- helpers ----------

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func jsonField(body, key string) string {
	needle := `"` + key + `"`
	i := strings.Index(body, needle)
	if i < 0 {
		return ""
	}
	rest := body[i+len(needle):]
	c := strings.IndexByte(rest, ':')
	if c < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[c+1:])
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	rest = rest[1:]
	var b strings.Builder
	for i := 0; i < len(rest); i++ {
		if rest[i] == '\\' && i+1 < len(rest) {
			b.WriteByte(rest[i+1])
			i++
			continue
		}
		if rest[i] == '"' {
			break
		}
		b.WriteByte(rest[i])
	}
	return b.String()
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}
