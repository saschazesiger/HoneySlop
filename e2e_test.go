package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// newTestApp builds a fully wired App without network servers.
func newTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	world, err := LoadOrCreateWorld(dir)
	if err != nil {
		t.Fatal(err)
	}
	hub := NewHub()
	a := &App{cfg: cfg, store: store, hub: hub, dataDir: dir,
		geo: NewGeoResolver(store, hub), llm: NewLLM(cfg), limiter: NewRateLimiter(cfg),
		logins: NewLoginLimiter(), cache: NewPathCache(dir)}
	a.setWorld(world)
	return a
}

// shell runs one terminal command over ServeHTTP, keeping the session cookie, returning the JSON reply.
type termClient struct {
	t      *testing.T
	a      *App
	cookie string
}

func (tc *termClient) run(cmd string) map[string]any {
	body, _ := json.Marshal(map[string]string{"cmd": cmd})
	req := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:51000"
	if tc.cookie != "" {
		req.Header.Set("Cookie", tc.cookie)
	}
	rec := httptest.NewRecorder()
	tc.a.ServeHTTP(rec, req)
	if c := rec.Header().Get("Set-Cookie"); c != "" && strings.HasPrefix(c, termCookie) {
		tc.cookie = strings.SplitN(c, ";", 2)[0]
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		tc.t.Fatalf("run %q: non-JSON reply: %s", cmd, rec.Body.String())
	}
	return out
}

func (tc *termClient) out(cmd string) string {
	r := tc.run(cmd)
	s, _ := r["output"].(string)
	return s
}

func milestonesOf(t *testing.T, a *App, ip string) string {
	info, err := a.store.GetIP(ip)
	if err != nil {
		return ""
	}
	return info.Milestones
}

// TestEndToEndKillChain walks a realistic attacker from recon to root through the real handlers,
// asserting that only genuine credentials work and that milestones advance in order.
func TestEndToEndKillChain(t *testing.T) {
	a := newTestApp(t)
	w := a.world()
	ip := "203.0.113.7"
	tc := &termClient{t: t, a: a}

	// 1. recon in the web shell
	if got := tc.out("whoami"); got != "www-data" {
		t.Fatalf("whoami = %q", got)
	}
	tc.run("") // page bootstrap style empty
	if got := tc.out("pwd"); got != termDefaultCwd {
		t.Fatalf("pwd = %q", got)
	}

	// 2. /etc/shadow is NOT readable
	if got := tc.out("cat /etc/shadow"); !strings.Contains(got, "Permission denied") {
		t.Fatalf("shadow should be denied: %q", got)
	}

	// 3. find credentials: the world-readable backup script leaks the deploy + backup passwords
	script := tc.out("cat /opt/scripts/db-backup.sh")
	if !strings.Contains(script, w.Unix["deploy"].Password) {
		t.Fatalf("backup script should contain deploy password")
	}
	if ms := milestonesOf(t, a, ip); !strings.Contains(ms, msCreds) {
		t.Fatalf("reading the backup script should reach creds, got %q", ms)
	}

	// 4. the .env leaks the DB password too
	env := tc.out("cat /var/www/connect/.env")
	if !strings.Contains(env, w.MySQL["connect_app"].Password) {
		t.Fatal(".env should contain the real DB password")
	}

	// 5. database access: a wrong password is rejected, the real one works (milestone db)
	wrong := tc.out(`mysql -h db-prod-01.internal.veltrona-group.com -u connect_app -phunter2 -e "show databases"`)
	if !strings.Contains(strings.ToLower(wrong), "access denied") {
		t.Fatalf("wrong mysql password must be denied: %q", wrong)
	}
	if strings.Contains(milestonesOf(t, a, ip), msDB) {
		t.Fatal("db milestone must not be reached with a wrong password")
	}
	good := tc.out(`mysql -h db-prod-01.internal.veltrona-group.com -u connect_app -p` + w.MySQL["connect_app"].Password + ` -e "show databases"`)
	if !strings.Contains(good, worldAppDB) {
		t.Fatalf("correct mysql login should list databases: %q", good)
	}
	if !strings.Contains(milestonesOf(t, a, ip), msDB) {
		t.Fatal("correct mysql login should reach the db milestone")
	}

	// 6. lateral movement: the deploy password (reused in the backup script) lets us su deploy
	r := tc.run("su deploy")
	if p, _ := r["prompt"].(string); p != "Password: " {
		t.Fatalf("su deploy should prompt for a password, got %+v", r)
	}
	if got := tc.out("wrongpassword"); !strings.Contains(got, "Authentication failure") {
		t.Fatalf("wrong su password must fail: %q", got)
	}
	tc.run("su deploy")
	esc := tc.run(w.Unix["deploy"].Password)
	if u, _ := esc["user"].(string); u != "deploy" {
		t.Fatalf("correct su should switch to deploy, got %+v", esc)
	}
	if !strings.Contains(milestonesOf(t, a, ip), msUser) {
		t.Fatal("su deploy should reach the user milestone")
	}
	if got := tc.out("whoami"); got != "deploy" {
		t.Fatalf("after su, whoami = %q", got)
	}

	// 7. privilege escalation: su root with the real root password yields a root shell
	tc.run("su root")
	root := tc.run(w.Unix["root"].Password)
	if u, _ := root["user"].(string); u != "root" {
		t.Fatalf("su root with the real password should succeed, got %+v", root)
	}
	if !strings.Contains(milestonesOf(t, a, ip), msRoot) {
		t.Fatal("su root should reach the root milestone")
	}
	// as root, /etc/shadow is now readable
	if got := tc.out("cat /etc/shadow"); !strings.Contains(got, "root:$6$") {
		t.Fatalf("root should read /etc/shadow: %q", got)
	}

	// final: the kill chain is fully recorded, in order
	if ms := milestonesOf(t, a, ip); ms != "creds,db,user,root" {
		t.Fatalf("final milestones = %q, want creds,db,user,root", ms)
	}
}

// TestEndToEndHTTPLogin exercises the credential-gated web realms through ServeHTTP.
func TestEndToEndHTTPLogin(t *testing.T) {
	a := newTestApp(t)
	w := a.world()

	do := func(method, path, ctype, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		req.RemoteAddr = "198.51.100.9:4444"
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, req)
		return rec
	}

	// .env leak over plain HTTP
	rec := do("GET", "/.env", "", "")
	if !strings.Contains(rec.Body.String(), w.MySQL["connect_app"].Password) {
		t.Fatal("GET /.env should leak the real DB password")
	}

	// wrong phpMyAdmin credentials are rejected, right ones authenticate
	rec = do("POST", "/phpmyadmin/index.php", "application/x-www-form-urlencoded", "pma_username=connect_app&pma_password=letmein")
	if rec.Code == http.StatusFound {
		t.Fatal("wrong phpMyAdmin password must not authenticate")
	}
	form := "pma_username=connect_app&pma_password=" + wwwFormEncode(w.MySQL["connect_app"].Password)
	rec = do("POST", "/phpmyadmin/index.php", "application/x-www-form-urlencoded", form)
	if rec.Code != http.StatusFound {
		t.Fatalf("correct phpMyAdmin login should redirect, got %d", rec.Code)
	}
	if ms := milestonesOf(t, a, "198.51.100.9"); !strings.Contains(ms, msDB) {
		t.Fatalf("phpMyAdmin login should reach db milestone, got %q", ms)
	}
}

func wwwFormEncode(s string) string {
	r := strings.NewReplacer("%", "%25", "+", "%2B", "&", "%26", "=", "%3D", "#", "%23", " ", "+")
	return r.Replace(s)
}
