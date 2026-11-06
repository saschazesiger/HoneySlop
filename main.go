package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

var version = "dev"

type App struct {
	cfg     *ConfigStore
	store   *Store
	hub     *Hub
	geo     *GeoResolver
	llm     *LLM
	limiter *RateLimiter
	logins  *LoginLimiter
	cache   *PathCache
	eng     atomic.Pointer[engineSet] // world + its engines, swapped atomically on regenerate
	dataDir string
	domain  string
}

// engineSet bundles the world and the engines derived from it, so "regenerate world" can publish a
// fully consistent new set with a single atomic store (no torn reads from concurrent handlers).
type engineSet struct {
	world  *World
	mysql  *MySQLServer
	shell  *ShellEngine
	webapp *WebApp
}

// setWorld builds the engines for w and publishes them atomically.
func (a *App) setWorld(w *World) {
	my := NewMySQLServer(w)
	es := &engineSet{world: w, mysql: my, shell: NewShellEngine(w, my)}
	es.webapp = NewWebApp(a, w)
	a.eng.Store(es)
}

func (a *App) world() *World       { return a.eng.Load().world }
func (a *App) mysql() *MySQLServer { return a.eng.Load().mysql }
func (a *App) shell() *ShellEngine { return a.eng.Load().shell }
func (a *App) webapp() *WebApp     { return a.eng.Load().webapp }

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// normalizeDomain accepts "pot.example.com", "https://pot.example.com/", "pot.example.com:443".
func normalizeDomain(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime)
	dataDir := flag.String("data", env("DATA_DIR", "./data"), "data directory (config.json, honeyslop.db, certs)")
	httpAddr := flag.String("http", env("HTTP_ADDR", ":80"), "HTTP listen address")
	httpsAddr := flag.String("https", env("HTTPS_ADDR", ":443"), "HTTPS listen address")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "HoneySlop %s, AI powered honeypot\n\nusage: honeyslop [flags] [domain]\n\n", version)
		flag.PrintDefaults()
	}
	flag.Parse()

	domain := normalizeDomain(flag.Arg(0))
	if domain == "" {
		domain = normalizeDomain(os.Getenv("DOMAIN"))
	}

	if err := os.MkdirAll(filepath.Join(*dataDir, "certs"), 0o700); err != nil {
		log.Fatalf("data dir: %v", err)
	}
	cfg, err := LoadConfig(*dataDir)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	// optional: pre-set the admin password instead of creating it on first visit of /pot
	if pw := os.Getenv("ADMIN_PASSWORD"); pw != "" && cfg.Get().PasswordHash == "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("ADMIN_PASSWORD: %v", err)
		}
		_, _ = cfg.Update(func(c *Config) { c.PasswordHash = string(hash) })
	}
	store, err := OpenStore(filepath.Join(*dataDir, "honeyslop.db"))
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	hub := NewHub()
	world, err := LoadOrCreateWorld(*dataDir)
	if err != nil {
		log.Fatalf("world: %v", err)
	}
	app := &App{
		cfg: cfg, store: store, hub: hub, domain: domain, dataDir: *dataDir,
		geo:     NewGeoResolver(store, hub),
		llm:     NewLLM(cfg),
		limiter: NewRateLimiter(cfg),
		logins:  NewLoginLimiter(),
		cache:   NewPathCache(*dataDir),
	}
	app.setWorld(world)
	// re-resolve IPs whose lookup never finished (e.g. restart)
	if ips, err := store.ListIPs("", 500); err == nil {
		for _, i := range ips {
			if i.Geo == "pending" {
				app.geo.Resolve(i.IP)
			}
		}
	}

	go app.janitor()

	selfSigned, err := loadOrCreateSelfSigned(filepath.Join(*dataDir, "certs"), domain)
	if err != nil {
		log.Fatalf("self-signed cert: %v", err)
	}

	var handler http.Handler = app
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	if domain != "" {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domain),
			Cache:      autocert.DirCache(filepath.Join(*dataDir, "certs")),
			Email:      os.Getenv("ACME_EMAIL"),
		}
		handler = m.HTTPHandler(app) // answers HTTP-01 challenges, everything else goes to the app (no redirect)
		tlsCfg.NextProtos = append(tlsCfg.NextProtos, acme.ALPNProto)
		var acmeMu sync.Mutex
		var acmeBackoff time.Time // avoid hammering Let's Encrypt while DNS isn't ready yet
		tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), domain) {
				acmeMu.Lock()
				wait := time.Now().Before(acmeBackoff)
				acmeMu.Unlock()
				isChallenge := len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acme.ALPNProto
				if !wait || isChallenge {
					c, err := m.GetCertificate(hello)
					if err == nil {
						return c, nil
					}
					log.Printf("acme: %v (serving self-signed, retry in 2m)", err)
					acmeMu.Lock()
					acmeBackoff = time.Now().Add(2 * time.Minute)
					acmeMu.Unlock()
				}
			}
			return selfSigned, nil
		}
	} else {
		tlsCfg.Certificates = []tls.Certificate{*selfSigned}
	}

	quiet := log.New(io.Discard, "", 0) // scanners cause endless handshake errors
	mk := func(addr string) *http.Server {
		return &http.Server{
			Addr: addr, Handler: handler, ErrorLog: quiet, MaxHeaderBytes: 64 << 10,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 120 * time.Second, IdleTimeout: 120 * time.Second,
		}
	}
	httpSrv, httpsSrv := mk(*httpAddr), mk(*httpsAddr)
	httpsSrv.TLSConfig = tlsCfg

	errc := make(chan error, 2)
	go func() { errc <- httpSrv.ListenAndServe() }()
	go func() { errc <- httpsSrv.ListenAndServeTLS("", "") }()

	host := domain
	if host == "" {
		host = "<server-ip>"
	}
	log.Printf("🍯 HoneySlop %s is running", version)
	log.Printf("   honeypot  → http://%s  https://%s  (http %s, https %s)", host, host, *httpAddr, *httpsAddr)
	log.Printf("   dashboard → https://%s/pot", host)
	if cfg.Get().PasswordHash == "" {
		log.Printf("   ⚠ no admin password yet, open /pot now to create one")
	}
	if domain == "" {
		log.Printf("   no domain given: serving a self-signed certificate (pass a domain to get Let's Encrypt)")
	}
	log.Printf("   data      → %s", *dataDir)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	case <-sig:
		log.Printf("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		_ = httpsSrv.Shutdown(ctx)
	}
}

// ServeHTTP routes: /pot → admin, / → terminal, everything else → AI honeypot.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("panic: %v", rec)
			http.Error(w, "", http.StatusInternalServerError)
		}
	}()
	p := r.URL.Path
	if p == "/pot" || strings.HasPrefix(p, "/pot/") {
		a.handleAdmin(w, r)
		return
	}
	if p == "/" && r.URL.RawQuery == "" {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			a.handleTerminalPage(w, r)
			return
		case http.MethodPost:
			body := readBody(r)
			if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") && strings.Contains(body, `"cmd"`) {
				a.handleTerminalCommand(w, r, body)
				return
			}
			r.Body = io.NopCloser(strings.NewReader(body))
		}
	}
	a.handleHoneypot(w, r)
}

// janitor enforces data retention and sweeps in-memory limiter state.
func (a *App) janitor() {
	for {
		c := a.cfg.Get()
		if n, err := a.store.Prune(time.Duration(c.RetentionDays)*24*time.Hour, c.MaxEvents); err != nil {
			log.Printf("retention: %v", err)
		} else if n > 0 {
			log.Printf("retention: deleted %d old events", n)
		}
		a.limiter.Sweep()
		a.logins.Sweep()
		time.Sleep(15 * time.Minute)
	}
}

func loadOrCreateSelfSigned(dir, domain string) (*tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, "selfsigned.crt"), filepath.Join(dir, "selfsigned.key")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return &c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	cn := termHost + ".veltrona-group.com"
	names := []string{cn, "localhost"}
	if domain != "" {
		cn, names = domain, append([]string{domain}, names...)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	return &c, err
}
