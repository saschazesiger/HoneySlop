package main

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testWorld(t *testing.T) *World {
	t.Helper()
	w, err := GenerateWorld()
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestHashesMatchPlaintext(t *testing.T) {
	w := testWorld(t)
	// unix sha512-crypt
	for name, a := range w.Unix {
		if a.Password == "" {
			continue
		}
		salt := a.Hash
		if !strings.HasPrefix(salt, "$6$") {
			t.Fatalf("%s hash not sha512: %s", name, salt)
		}
		parts := strings.SplitN(salt[3:], "$", 2)
		if got := sha512Crypt(a.Password, parts[0]); got != a.Hash {
			t.Fatalf("unix %s: crypt mismatch", name)
		}
	}
	// mysql native
	for name, a := range w.MySQL {
		if mysqlNativeHash(a.Password) != a.Hash {
			t.Fatalf("mysql %s: native hash mismatch", name)
		}
	}
	// portal bcrypt + wp phpass
	for _, u := range w.AppUsers {
		if !strings.HasPrefix(u.Hash, "$2y$") {
			t.Fatalf("portal %s: not bcrypt", u.Email)
		}
	}
	for _, u := range w.WPUsers {
		if phpassWithSalt(u.Password, u.Hash[:12]) != u.Hash {
			t.Fatalf("wp %s: phpass mismatch", u.Login)
		}
	}
}

func TestWorldAuth(t *testing.T) {
	w := testWorld(t)
	if !w.CheckUnix("deploy", w.Unix["deploy"].Password) {
		t.Fatal("deploy password should authenticate")
	}
	if w.CheckUnix("deploy", "wrongpass") {
		t.Fatal("wrong deploy password must fail")
	}
	if w.CheckUnix("www-data", "anything") {
		t.Fatal("www-data is a locked account, must never authenticate")
	}
	if _, ok := w.CheckMySQL("connect_app", w.MySQL["connect_app"].Password); !ok {
		t.Fatal("connect_app real password must work")
	}
	if _, ok := w.CheckMySQL("connect_app", "Password123!"); ok {
		t.Fatal("wrong mysql password must be rejected")
	}
	if _, ok := w.CheckMySQL("connect_app", w.MySQL["root"].Password); ok {
		t.Fatal("another account's password must not work for connect_app")
	}
}

func TestVFSPermissions(t *testing.T) {
	w := testWorld(t)
	cases := []struct {
		path, user, want string
		deny             bool
	}{
		{"/etc/shadow", "www-data", "r", true},
		{"/etc/shadow", "root", "r", false},
		{"/etc/passwd", "www-data", "r", false},
		{"/root/.my.cnf", "www-data", "r", true},
		{"/root/.my.cnf", "deploy", "r", true},
		{"/root/.my.cnf", "root", "r", false},
		{"/var/www/connect/.env", "www-data", "r", false},     // group www-data can read
		{"/var/www/connect/.env", "deploy", "r", false},       // owner
		{"/opt/scripts/db-backup.sh", "www-data", "r", false}, // world readable
		{"/home/deploy/.ssh/id_ed25519", "www-data", "r", true},
	}
	for _, c := range cases {
		err := w.AccessError(c.user, c.path, c.want)
		if (err != "") != c.deny {
			t.Errorf("AccessError(%s, %s, %s) = %q, denyWanted=%v", c.user, c.path, c.want, err, c.deny)
		}
	}
	// the backup script and .env must actually contain working secrets
	if !w.LeaksSecret(w.Lookup("/opt/scripts/db-backup.sh").Content) {
		t.Error("db-backup.sh should leak a real secret")
	}
	if !w.LeaksSecret(w.Lookup("/var/www/connect/.env").Content) {
		t.Error(".env should leak a real secret")
	}
}

func TestShellDeterministic(t *testing.T) {
	w := testWorld(t)
	e := NewShellEngine(w, nil)
	ctx := context.Background()
	c := &ShellCtx{User: "www-data", Cwd: "/var/www/connect"}

	run := func(cmd string) ShellResult { return e.Run(ctx, c, cmd) }

	if r := run("whoami"); !r.Handled || r.Output != "www-data" {
		t.Fatalf("whoami: %+v", r)
	}
	if r := run("pwd"); r.Output != "/var/www/connect" {
		t.Fatalf("pwd: %+v", r)
	}
	if r := run("id"); !strings.Contains(r.Output, "uid=33(www-data)") {
		t.Fatalf("id: %q", r.Output)
	}
	// reading /etc/shadow is denied
	if r := run("cat /etc/shadow"); !r.Handled || !strings.Contains(r.Output, "Permission denied") {
		t.Fatalf("cat shadow: %+v", r)
	}
	// reading /etc/passwd works and is the real file
	if r := run("cat /etc/passwd"); !r.Handled || !strings.Contains(r.Output, "deploy:x:1001") {
		t.Fatalf("cat passwd: %+v", r)
	}
	// reading .env leaks creds
	r := run("cat .env")
	if !r.Handled || !strings.Contains(r.Output, "DB_PASSWORD") {
		t.Fatalf("cat .env: %+v", r)
	}
	if !containsFlag(r.Flags, msCreds) {
		t.Fatalf("cat .env should flag creds: %+v", r.Flags)
	}
}

func TestShellSuEscalation(t *testing.T) {
	w := testWorld(t)
	e := NewShellEngine(w, nil)
	ctx := context.Background()
	c := &ShellCtx{User: "www-data", Cwd: "/var/www/connect"}

	// su deploy prompts for a password
	r := e.Run(ctx, c, "su deploy")
	if r.Pending == nil || r.Prompt != "Password: " {
		t.Fatalf("su deploy should prompt: %+v", r)
	}
	// wrong password fails
	bad := e.Continue(ctx, c, r.Pending, "nope")
	if bad.User == "deploy" || !strings.Contains(bad.Output, "Authentication failure") {
		t.Fatalf("wrong su password must fail: %+v", bad)
	}
	// correct password switches user and flags lateral movement
	good := e.Continue(ctx, c, r.Pending, w.Unix["deploy"].Password)
	if good.User != "deploy" {
		t.Fatalf("correct su should switch user: %+v", good)
	}
	if !containsFlag(good.Flags, msUser) {
		t.Fatalf("su deploy should flag user milestone: %+v", good.Flags)
	}
	// su root with a wrong password fails
	rr := e.Run(ctx, c, "su")
	if out := e.Continue(ctx, c, rr.Pending, "guess"); out.User == "root" {
		t.Fatal("su root must not succeed with a guessed password")
	}
}

func TestShellSudoNotSudoer(t *testing.T) {
	w := testWorld(t)
	e := NewShellEngine(w, nil)
	ctx := context.Background()
	c := &ShellCtx{User: "www-data", Cwd: "/var/www"}
	// sudo -l shows www-data may not run sudo at all
	if r := e.Run(ctx, c, "sudo -l"); !strings.Contains(r.Output, "may not run sudo") {
		t.Fatalf("sudo -l for www-data: %q", r.Output)
	}
	// three wrong password attempts: never a root shell, ends in the real sudoers rejection
	r := e.Run(ctx, c, "sudo su -")
	for i := 0; i < 3 && r.Pending != nil; i++ {
		r = e.Continue(ctx, c, r.Pending, "whatever")
		if r.User == "root" {
			t.Fatal("www-data must never gain root via sudo")
		}
	}
	if !strings.Contains(r.Output, "not in the sudoers file") && !strings.Contains(r.Output, "incorrect password") {
		t.Fatalf("expected sudoers rejection, got %q", r.Output)
	}
}

func TestWebAppFileLeak(t *testing.T) {
	a := &App{}
	a.setWorld(testWorld(t))
	// direct .env
	req := httptest.NewRequest("GET", "/.env", nil)
	rep, flags, ok := a.webapp().Handle(req, "")
	if !ok || !strings.Contains(rep.body, "DB_PASSWORD") {
		t.Fatalf("GET /.env should leak env: ok=%v", ok)
	}
	if !containsFlag(flags, msCreds) {
		t.Fatal("env leak should flag creds")
	}
	// LFI traversal
	req = httptest.NewRequest("GET", "/index.php?page=../../../../var/www/connect/.env", nil)
	rep, _, ok = a.webapp().Handle(req, "")
	if !ok || !strings.Contains(rep.body, "connect_app") {
		t.Fatalf("LFI should leak env: ok=%v body=%.60q", ok, rep.body)
	}
	// /etc/passwd via traversal
	req = httptest.NewRequest("GET", "/download?file=/etc/passwd", nil)
	rep, _, ok = a.webapp().Handle(req, "")
	if !ok || !strings.Contains(rep.body, "root:x:0:0") {
		t.Fatalf("LFI passwd: ok=%v", ok)
	}
	// www-data cannot read /etc/shadow via LFI → not handled (LLM 404s)
	req = httptest.NewRequest("GET", "/download?file=../../../../etc/shadow", nil)
	if _, _, ok = a.webapp().Handle(req, ""); ok {
		t.Fatal("LFI of /etc/shadow must not succeed as www-data")
	}
}

func TestWebAppLogins(t *testing.T) {
	w := testWorld(t)
	a := &App{}
	a.setWorld(w)

	post := func(path string, form url.Values) (*webReply, []string, bool) {
		body := form.Encode()
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return a.webapp().Handle(req, body)
	}

	// WordPress: find the weak user
	var weak *WPUser
	for i := range w.WPUsers {
		if w.WPUsers[i].Weak {
			weak = &w.WPUsers[i]
		}
	}
	if weak != nil {
		rep, flags, ok := post("/blog/wp-login.php", url.Values{"log": {weak.Login}, "pwd": {weak.Password}})
		if !ok || rep.status != 302 || !containsFlag(flags, msLogin) {
			t.Fatalf("correct wp login should 302+login: %+v %v", rep, flags)
		}
		rep, flags, _ = post("/blog/wp-login.php", url.Values{"log": {weak.Login}, "pwd": {"WrongPass1"}})
		if rep.status == 302 || containsFlag(flags, msLogin) {
			t.Fatal("wrong wp password must not log in")
		}
	}

	// phpMyAdmin: only real mysql creds
	rep, flags, ok := post("/phpmyadmin/index.php", url.Values{"pma_username": {"connect_app"}, "pma_password": {w.MySQL["connect_app"].Password}})
	if !ok || rep.status != 302 || !containsFlag(flags, msDB) {
		t.Fatalf("correct pma login should 302+db: %+v %v", rep, flags)
	}
	rep, _, _ = post("/phpmyadmin/index.php", url.Values{"pma_username": {"connect_app"}, "pma_password": {"hunter2"}})
	if rep.status == 302 || !strings.Contains(rep.body, "1045") {
		t.Fatal("wrong pma password must be rejected with #1045")
	}

	// Portal login
	var cust *AppUser
	for i := range w.AppUsers {
		if w.AppUsers[i].Role == "customer" {
			cust = &w.AppUsers[i]
			break
		}
	}
	rep, flags, ok = post("/login", url.Values{"email": {cust.Email}, "password": {cust.Password}})
	if !ok || rep.status != 302 || !containsFlag(flags, msLogin) {
		t.Fatalf("correct portal login should 302+login: %+v %v", rep, flags)
	}
	rep, _, _ = post("/login", url.Values{"email": {cust.Email}, "password": {"nope"}})
	if rep.status == 302 {
		t.Fatal("wrong portal password must not log in")
	}
}

func TestMergeMilestones(t *testing.T) {
	got, newly := MergeMilestones("creds", []string{"db", "creds", "root"})
	if got != "creds,db,root" {
		t.Fatalf("order wrong: %q", got)
	}
	if len(newly) != 2 {
		t.Fatalf("newly=%v", newly)
	}
	if _, n := MergeMilestones("creds,db", []string{"db"}); len(n) != 0 {
		t.Fatalf("no new milestones expected: %v", n)
	}
}

func TestWorldPersistenceStable(t *testing.T) {
	dir := t.TempDir()
	w1, err := LoadOrCreateWorld(dir)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := LoadOrCreateWorld(dir)
	if err != nil {
		t.Fatal(err)
	}
	if w1.Seed != w2.Seed || w1.MySQL["connect_app"].Password != w2.MySQL["connect_app"].Password {
		t.Fatal("world must be stable across reloads")
	}
}

func TestSudoNopasswdNotRoot(t *testing.T) {
	w := testWorld(t)
	e := NewShellEngine(w, nil)
	ctx := context.Background()
	c := &ShellCtx{User: "deploy", Cwd: "/home/deploy"}
	// deploy's NOPASSWD entry runs a service command as root, but that is NOT a root shell
	r := e.Run(ctx, c, "sudo systemctl reload nginx")
	if containsFlag(r.Flags, msRoot) {
		t.Fatalf("whitelisted NOPASSWD systemctl must not award the root milestone: %+v", r.Flags)
	}
	if r.User == "root" {
		t.Fatal("NOPASSWD service command must not switch the user to root")
	}
	// deploy cannot use su root via a password it does not know
	rr := e.Run(ctx, c, "su")
	if out := e.Continue(ctx, c, rr.Pending, "guess"); out.User == "root" {
		t.Fatal("deploy must not become root with a guessed password")
	}
}

func TestRegenerateRaceSafe(t *testing.T) {
	// two pre-built worlds (world generation is bcrypt-heavy; swapping them is what we want to race)
	w1, w2 := testWorld(t), testWorld(t)
	a := &App{}
	a.setWorld(w1)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 2000; i++ {
			if i%2 == 0 { // operator "regenerate world": atomic engine swap
				a.setWorld(w1)
			} else {
				a.setWorld(w2)
			}
		}
		close(done)
	}()
	for i := 0; i < 2_000_000; i++ {
		select {
		case <-done:
			return
		default:
			// concurrent readers like the live handlers: each accessor returns a consistent set
			_ = a.world().Seed
			_ = a.shell()
			_ = a.mysql()
			_ = a.webapp().world.Created
		}
	}
	<-done
}
