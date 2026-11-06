package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

// The "world" is the deterministic backbone of the honeypot: real (generated) credentials, accounts and
// keys of the fictional company. It is created once per installation (world.json in the data dir), so
// every attacker meets the same machine, and only the credentials that really exist work. The LLM only
// renders flavour around these facts; authentication and privilege decisions are made in Go.

const worldVersion = 1

// fixed infrastructure of the fictional company
const (
	worldDomain     = "veltrona-group.com"
	worldHostIP     = "10.20.2.43"
	worldDBHost     = "db-prod-01.internal.veltrona-group.com"
	worldDBIP       = "10.20.4.11"
	worldBackupHost = "backup-01.internal.veltrona-group.com"
	worldMySQLVer   = "5.7.42-0ubuntu0.18.04.1-log"
	worldAppDB      = "veltrona_connect"
	worldWPDB       = "veltrona_wp"
)

type UnixAccount struct {
	Name     string   `json:"name"`
	UID      int      `json:"uid"`
	GID      int      `json:"gid"`
	Gecos    string   `json:"gecos"`
	Home     string   `json:"home"`
	Shell    string   `json:"shell"`
	Groups   []string `json:"groups"`             // supplementary groups
	Password string   `json:"password,omitempty"` // empty = locked account
	Hash     string   `json:"hash"`               // /etc/shadow field ($6$... or * / !)
}

type MySQLAccount struct {
	User     string   `json:"user"`
	Host     string   `json:"host"` // mysql.user host column
	Password string   `json:"password"`
	Hash     string   `json:"hash"` // mysql_native_password (*HEX)
	DBs      []string `json:"dbs"`  // databases this account may use, "*" = all
	ReadOnly bool     `json:"read_only"`
	Grants   []string `json:"grants"` // SHOW GRANTS lines
}

// AppUser is a user of the Laravel customer portal "Veltrona Connect" (table users).
type AppUser struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Role       string `json:"role"` // admin, staff, customer
	CustomerID int    `json:"customer_id,omitempty"`
	Password   string `json:"password"`
	Hash       string `json:"hash"` // bcrypt $2y$10$
	Weak       bool   `json:"weak"` // crackable with a wordlist
}

// WPUser is a user of the legacy WordPress blog under /blog (table wp_users).
type WPUser struct {
	ID       int    `json:"id"`
	Login    string `json:"login"`
	Email    string `json:"email"`
	Display  string `json:"display"`
	Role     string `json:"role"` // administrator, editor, author
	Password string `json:"password"`
	Hash     string `json:"hash"` // phpass $P$B...
	Weak     bool   `json:"weak"`
}

type WorldKeys struct {
	AppKey       string   `json:"app_key"` // base64:...
	AWSKeyID     string   `json:"aws_key_id"`
	AWSSecret    string   `json:"aws_secret"`
	MailUser     string   `json:"mail_user"`
	MailPassword string   `json:"mail_password"`
	StripeSecret string   `json:"stripe_secret"`
	GitLabToken  string   `json:"gitlab_token"`
	JenkinsToken string   `json:"jenkins_token"`
	SlackWebhook string   `json:"slack_webhook"`
	PusherSecret string   `json:"pusher_secret"`
	SAPPassword  string   `json:"sap_password"`
	JWTSecret    string   `json:"jwt_secret"`
	WPAuthKeys   []string `json:"wp_auth_keys"`
	DeploySSHKey string   `json:"deploy_ssh_key"` // OpenSSH private key (ed25519)
	DeploySSHPub string   `json:"deploy_ssh_pub"`
	RootSSHKey   string   `json:"root_ssh_key"`
	RootSSHPub   string   `json:"root_ssh_pub"`
	OpsSSHPub    string   `json:"ops_ssh_pub"` // admin laptop key in authorized_keys
	ContainerID  string   `json:"container_id"`
}

type World struct {
	Version  int                      `json:"version"`
	Created  time.Time                `json:"created"`
	Seed     uint64                   `json:"seed"` // drives deterministic data generation (DB rows, file dates)
	Unix     map[string]*UnixAccount  `json:"unix"`
	MySQL    map[string]*MySQLAccount `json:"mysql"`
	AppUsers []AppUser                `json:"app_users"`
	WPUsers  []WPUser                 `json:"wp_users"`
	Keys     WorldKeys                `json:"keys"`

	files map[string]*VFile // derived, see vfs.go
	dbs   []Database        // derived, see worlddata.go
}

// ---------- persistence ----------

func worldPath(dir string) string { return filepath.Join(dir, "world.json") }

// LoadOrCreateWorld reads world.json or generates a fresh world.
func LoadOrCreateWorld(dir string) (*World, error) {
	data, err := os.ReadFile(worldPath(dir))
	if err == nil {
		var w World
		if err := json.Unmarshal(data, &w); err != nil {
			return nil, fmt.Errorf("world.json: %w", err)
		}
		if w.Version == worldVersion && w.Unix["deploy"] != nil {
			w.derive()
			return &w, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	w, err := GenerateWorld()
	if err != nil {
		return nil, err
	}
	return w, w.Save(dir)
}

func (w *World) Save(dir string) error {
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	tmp := worldPath(dir) + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, worldPath(dir))
}

func (w *World) derive() {
	w.files = buildFiles(w)
	w.dbs = buildDatabases(w)
}

// ---------- random helpers (crypto/rand: secrets must not be predictable) ----------

const (
	alnum      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	upperAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	lowerHex   = "0123456789abcdef"
)

func rint(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(v.Int64())
}

func rstr(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rint(len(alphabet))]
	}
	return string(b)
}

func pick[T any](xs []T) T { return xs[rint(len(xs))] }

// strongPassword looks machine generated (password manager / pwgen).
func strongPassword(n int) string {
	for {
		p := rstr(alnum+"#%+=-_!", n)
		if strings.ContainsAny(p, "0123456789") && strings.ContainsAny(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") && strings.ContainsAny(p, "abcdefghijklmnopqrstuvwxyz") {
			return p
		}
	}
}

var pwWords = []string{"Rotterdam", "Basel", "Zugersee", "Gotthard", "Frachtbrief", "Container", "Spedition", "Pilatus",
	"Matterhorn", "Rheinhafen", "Logistik", "Lagerhalle", "Hafenkran", "Alpenblick", "Sendung", "Palette", "Veltrona",
	"Rigi", "Saentis", "Lugano", "Brienz", "Gabelstapler", "Zollamt", "Kran", "Tessin"}

// humanPassword looks like something an admin typed and reused.
func humanPassword() string {
	w := pick(pwWords)
	year := 2017 + rint(8)
	switch rint(4) {
	case 0:
		return fmt.Sprintf("%s%d%s", w, year, pick([]string{"!", "#", "$", "?"}))
	case 1:
		return fmt.Sprintf("%s#%02d%s", w, 10+rint(90), pick([]string{"", "!", "x"}))
	case 2:
		return fmt.Sprintf("%s_%s%d", w, pick(pwWords), 1+rint(99))
	default:
		return fmt.Sprintf("%s.%d!%s", strings.ToLower(w), year, pick([]string{"", "Ops", "Prod"}))
	}
}

// weakPassword is crackable with a common wordlist + rules (realistic for end users).
func weakPassword() string {
	return pick([]string{"Sommer2023!", "Welcome2024!", "Zuerich2022", "Basel1893", "Herbst2023", "Logistik1!",
		"Fruehling24", "Veltrona1", "Passwort2022!", "Schweiz2021", "Winter2024!", "Freight2023"})
}

// ---------- hashes ----------

func bcryptHash(pw string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 10)
	if err != nil {
		panic(err)
	}
	return "$2y$" + string(h[4:]) // Laravel / PHP style prefix
}

func newSSHKey(comment string) (priv, pub string) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	block, err := ssh.MarshalPrivateKey(sk, comment)
	if err != nil {
		panic(err)
	}
	sp, err := ssh.NewPublicKey(pk)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(block)), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " " + comment
}

// ---------- generation ----------

func GenerateWorld() (*World, error) {
	w := &World{Version: worldVersion, Created: time.Now().UTC().Truncate(time.Second)}
	seed := make([]byte, 8)
	_, _ = rand.Read(seed)
	for _, b := range seed {
		w.Seed = w.Seed<<8 | uint64(b)
	}

	deployPW := humanPassword()
	ubuntuPW := strongPassword(18)
	rootPW := strongPassword(22)
	mk := func(name string, uid, gid int, gecos, home, shell, pw string, groups ...string) *UnixAccount {
		a := &UnixAccount{Name: name, UID: uid, GID: gid, Gecos: gecos, Home: home, Shell: shell, Groups: groups, Password: pw}
		if pw == "" {
			a.Hash = "*"
		} else {
			a.Hash = sha512Crypt(pw, rstr("./"+alnum, 16))
		}
		return a
	}
	w.Unix = map[string]*UnixAccount{
		"root":     mk("root", 0, 0, "root", "/root", "/bin/bash", rootPW),
		"ubuntu":   mk("ubuntu", 1000, 1000, "Ubuntu", "/home/ubuntu", "/bin/bash", ubuntuPW, "adm", "cdrom", "sudo", "dip", "plugdev", "lxd"),
		"deploy":   mk("deploy", 1001, 1001, "Deploy User,,,", "/home/deploy", "/bin/bash", deployPW, "www-data", "docker"),
		"www-data": mk("www-data", 33, 33, "www-data", "/var/www", "/usr/sbin/nologin", ""),
		"backup":   mk("backup", 34, 34, "backup", "/var/backups", "/usr/sbin/nologin", ""),
	}

	my := func(user, host, pw string, ro bool, dbs []string, grants ...string) *MySQLAccount {
		return &MySQLAccount{User: user, Host: host, Password: pw, Hash: mysqlNativeHash(pw), DBs: dbs, ReadOnly: ro, Grants: grants}
	}
	connectPW := strongPassword(20)
	wpPW := strongPassword(16)
	backupPW := humanPassword()
	mysqlRootPW := humanPassword()
	w.MySQL = map[string]*MySQLAccount{
		"connect_app": my("connect_app", "10.20.2.%", connectPW, false, []string{worldAppDB},
			"GRANT USAGE ON *.* TO 'connect_app'@'10.20.2.%'",
			"GRANT ALL PRIVILEGES ON `veltrona_connect`.* TO 'connect_app'@'10.20.2.%'"),
		"wp_blog": my("wp_blog", "10.20.2.%", wpPW, false, []string{worldWPDB},
			"GRANT USAGE ON *.* TO 'wp_blog'@'10.20.2.%'",
			"GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER ON `veltrona_wp`.* TO 'wp_blog'@'10.20.2.%'"),
		"backup": my("backup", "10.20.%", backupPW, true, []string{"*"},
			"GRANT SELECT, RELOAD, LOCK TABLES, SHOW VIEW, EVENT, TRIGGER ON *.* TO 'backup'@'10.20.%'"),
		"root": my("root", "%", mysqlRootPW, false, []string{"*"},
			"GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION",
			"GRANT PROXY ON ''@'' TO 'root'@'%' WITH GRANT OPTION"),
	}

	// Laravel portal users: staff + customer accounts. Exactly one admin and some customers are crackable.
	staff := []struct{ name, role string }{
		{"Daniel Kessler", "admin"}, {"Sandra Brunner", "admin"}, {"Marco Bianchi", "staff"}, {"Julia Wyss", "staff"},
		{"Tobias Hofmann", "staff"}, {"Aylin Demir", "staff"},
	}
	weakAdmin := rint(2)
	id := 1
	for i, s := range staff {
		first, last, _ := strings.Cut(s.name, " ")
		u := AppUser{ID: id, Name: s.name, Role: s.role, Email: strings.ToLower(asciiFold(first)+"."+asciiFold(last)) + "@" + worldDomain}
		if s.role == "admin" && i == weakAdmin {
			u.Password, u.Weak = weakPassword(), true
		} else {
			u.Password = strongPassword(14)
		}
		w.AppUsers = append(w.AppUsers, u)
		id++
	}
	customers := []struct{ name, domain string }{
		{"Lukas Meier", "alpenfrost.ch"}, {"Chiara Rossi", "rossi-import.it"}, {"Stefan Wagner", "wagner-maschinenbau.de"},
		{"Petra Novak", "novak-trade.pl"}, {"Jan de Vries", "devries-agro.nl"}, {"Nina Huber", "huber-pharma.ch"},
		{"Felix Baumann", "baumann-moebel.de"}, {"Elena Ferri", "ferri-tessile.it"},
	}
	for i, c := range customers {
		first, last, _ := strings.Cut(c.name, " ")
		u := AppUser{ID: id, Name: c.name, Role: "customer", CustomerID: 100 + i*7 + rint(5),
			Email: strings.ToLower(asciiFold(first)[:1]+"."+strings.ReplaceAll(asciiFold(last), " ", "")) + "@" + c.domain}
		if rint(3) == 0 {
			u.Password, u.Weak = weakPassword(), true
		} else {
			u.Password = strongPassword(12)
		}
		w.AppUsers = append(w.AppUsers, u)
		id++
	}
	for i := range w.AppUsers {
		w.AppUsers[i].Hash = bcryptHash(w.AppUsers[i].Password)
	}

	wp := []WPUser{
		{ID: 1, Login: "veltrona-admin", Email: "webmaster@" + worldDomain, Display: "Veltrona Web Team", Role: "administrator", Password: strongPassword(18)},
		{ID: 2, Login: "s.brunner", Email: "sandra.brunner@" + worldDomain, Display: "Sandra Brunner", Role: "editor", Password: weakPassword(), Weak: true},
		{ID: 3, Login: "m.keller", Email: "michael.keller@" + worldDomain, Display: "Michael Keller", Role: "author", Password: humanPassword()},
		{ID: 5, Login: "agentur-pixelwerk", Email: "support@pixelwerk-agentur.ch", Display: "Pixelwerk Agentur", Role: "administrator", Password: strongPassword(14)},
	}
	for i := range wp {
		wp[i].Hash = phpassHash(wp[i].Password)
	}
	w.WPUsers = wp

	k := &w.Keys
	appKey := make([]byte, 32)
	_, _ = rand.Read(appKey)
	k.AppKey = "base64:" + base64.StdEncoding.EncodeToString(appKey)
	k.AWSKeyID = "AKIA" + rstr(upperAlnum, 16)
	k.AWSSecret = rstr(alnum+"+/", 40)
	k.MailUser = "noreply-connect@" + worldDomain
	k.MailPassword = rstr("abcdefghijklmnopqrstuvwxyz", 16)
	k.StripeSecret = "sk_live_51" + rstr(alnum, 22) + rstr(alnum, 24) + rstr(alnum, 30)
	k.GitLabToken = "glpat-" + rstr(alnum+"-_", 20)
	k.JenkinsToken = "11" + rstr(lowerHex, 32)
	k.SlackWebhook = "https://hooks.slack.com/services/T0" + rstr(upperAlnum, 8) + "/B0" + rstr(upperAlnum, 9) + "/" + rstr(alnum, 24)
	k.PusherSecret = rstr(lowerHex, 20)
	k.SAPPassword = humanPassword()
	k.JWTSecret = rstr(alnum, 64)
	for i := 0; i < 8; i++ {
		k.WPAuthKeys = append(k.WPAuthKeys, rstr(alnum+"!@#$%^&*()-_[]{}<>~+=,.;:/?|", 64))
	}
	k.DeploySSHKey, k.DeploySSHPub = newSSHKey("deploy@web-prod-03")
	k.RootSSHKey, k.RootSSHPub = newSSHKey("root@web-prod-03")
	_, k.OpsSSHPub = newSSHKey("d.kessler@NB-ZG-0117")
	k.ContainerID = rstr(lowerHex, 64)

	w.derive()
	return w, nil
}

func asciiFold(s string) string {
	return strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "é", "e", "è", "e", " ", "").Replace(s)
}

// ---------- queries ----------

// AppUserByEmail finds a portal user (case-insensitive).
func (w *World) AppUserByEmail(email string) *AppUser {
	for i := range w.AppUsers {
		if strings.EqualFold(w.AppUsers[i].Email, strings.TrimSpace(email)) {
			return &w.AppUsers[i]
		}
	}
	return nil
}

// WPUserByLogin finds a WordPress user by login or email.
func (w *World) WPUserByLogin(login string) *WPUser {
	login = strings.TrimSpace(login)
	for i := range w.WPUsers {
		if strings.EqualFold(w.WPUsers[i].Login, login) || strings.EqualFold(w.WPUsers[i].Email, login) {
			return &w.WPUsers[i]
		}
	}
	return nil
}

// CheckMySQL validates a MySQL login. ok=false means "Access denied".
func (w *World) CheckMySQL(user, pw string) (*MySQLAccount, bool) {
	a := w.MySQL[user]
	if a == nil || a.Password != pw {
		return nil, false
	}
	return a, true
}

// CheckUnix validates a Unix password (su / ssh / sudo).
func (w *World) CheckUnix(user, pw string) bool {
	a := w.Unix[user]
	return a != nil && a.Password != "" && a.Password == pw
}

// Secret is a credential an attacker can find, with where it lives.
type Secret struct {
	Kind   string `json:"kind"`  // unix, mysql, portal, wordpress, api
	User   string `json:"user"`  // account / key name
	Value  string `json:"value"` // password or token
	Where  string `json:"where"` // where it can be found
	Grants string `json:"grants"`
}

// Secrets lists every credential with the place it leaks from (for the operator and milestone detection).
func (w *World) Secrets() []Secret {
	var out []Secret
	add := func(kind, user, value, where, grants string) {
		out = append(out, Secret{kind, user, value, where, grants})
	}
	add("mysql", "connect_app", w.MySQL["connect_app"].Password, "/var/www/connect/.env, LFI /download?file=../../.env", "veltrona_connect.*")
	add("mysql", "wp_blog", w.MySQL["wp_blog"].Password, "/var/www/blog/wp-config.php", "veltrona_wp.*")
	add("mysql", "backup", w.MySQL["backup"].Password, "/opt/scripts/db-backup.sh (world readable)", "SELECT on *.*")
	add("unix", "deploy", w.Unix["deploy"].Password, "/opt/scripts/db-backup.sh (sshpass, password reuse)", "su deploy, docker group → root")
	add("mysql", "root", w.MySQL["root"].Password, "/root/.my.cnf (root only)", "ALL on *.*")
	add("unix", "root", w.Unix["root"].Password, "not stored anywhere (only reachable via privilege escalation)", "root")
	add("unix", "ubuntu", w.Unix["ubuntu"].Password, "not stored anywhere", "sudo")
	for _, u := range w.AppUsers {
		where := "users table (bcrypt hash, strong password)"
		if u.Weak {
			where = "users table (bcrypt hash, crackable with wordlist)"
		}
		add("portal", u.Email, u.Password, where, u.Role)
	}
	for _, u := range w.WPUsers {
		where := "wp_users table (phpass hash, strong password)"
		if u.Weak {
			where = "wp_users table (phpass hash, crackable with wordlist)"
		}
		add("wordpress", u.Login, u.Password, where, u.Role)
	}
	add("api", "AWS_SECRET_ACCESS_KEY", w.Keys.AWSSecret, "/var/www/connect/.env", w.Keys.AWSKeyID)
	add("api", "MAIL_PASSWORD", w.Keys.MailPassword, "/var/www/connect/.env", w.Keys.MailUser)
	add("api", "STRIPE_SECRET", w.Keys.StripeSecret, "/var/www/connect/.env", "")
	add("api", "deploy ssh key", "id_ed25519", "/home/deploy/.ssh/id_ed25519", "deploy@web-prod-03")
	return out
}

// leakMarkers are distinctive secret values whose appearance in a response means "credentials obtained".
func (w *World) leakMarkers() []string {
	m := []string{w.MySQL["connect_app"].Password, w.MySQL["wp_blog"].Password, w.MySQL["backup"].Password,
		w.MySQL["root"].Password, w.Unix["deploy"].Password, w.Keys.AWSSecret, w.Keys.StripeSecret, w.Keys.MailPassword}
	for _, u := range w.AppUsers {
		m = append(m, u.Hash)
	}
	for _, u := range w.WPUsers {
		m = append(m, u.Hash)
	}
	if lines := strings.Split(w.Keys.DeploySSHKey, "\n"); len(lines) > 2 {
		m = append(m, lines[1])
	}
	return m
}

// LeaksSecret reports whether text contains any real secret of the world.
func (w *World) LeaksSecret(text string) bool {
	if len(text) < 8 {
		return false
	}
	for _, s := range w.leakMarkers() {
		if len(s) >= 8 && strings.Contains(text, s) {
			return true
		}
	}
	return false
}

// httpFacts tells the LLM which secrets and logins are handled deterministically, so its improvised
// pages stay consistent (it must not fake a successful login or invent the real .env credentials).
func (w *World) httpFacts() string {
	var emails []string
	for _, u := range w.AppUsers {
		emails = append(emails, u.Email)
	}
	return "\n\nCONSISTENCY FACTS (enforced by the real backend, never contradict):\n" +
		"- The app DB host is " + worldDBHost + " (" + worldDBIP + "), database " + worldAppDB + ", MySQL " + worldMySQLVer + ".\n" +
		"- Real secret files (.env, wp-config.php, /etc/passwd) and all login forms (WordPress /blog/wp-login.php, portal /login, /phpmyadmin) are served by the real backend, NOT by you. Never claim a login attempt succeeded, never emit a session cookie for an authenticated admin area, and never print database credentials, API keys or password hashes you invented - a wrong guess would be inconsistent with the real files. If a page you render would show such a secret, show a realistic login form or an access-denied/404 instead.\n" +
		"- Known portal user emails (do not invent different ones): " + strings.Join(emails, ", ") + ".\n"
}
