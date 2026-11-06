package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  ip TEXT NOT NULL,
  kind TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT '',
  scheme TEXT NOT NULL DEFAULT '',
  host TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  proto TEXT NOT NULL DEFAULT '',
  req_headers TEXT NOT NULL DEFAULT '{}',
  req_body TEXT NOT NULL DEFAULT '',
  status INTEGER NOT NULL DEFAULT 0,
  resp_headers TEXT NOT NULL DEFAULT '{}',
  resp_body TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  latency_ms INTEGER NOT NULL DEFAULT 0,
  tokens INTEGER NOT NULL DEFAULT 0,
  session TEXT NOT NULL DEFAULT '',
  cmd TEXT NOT NULL DEFAULT '',
  cwd TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip, id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session, id);

CREATE TABLE IF NOT EXISTS ips (
  ip TEXT PRIMARY KEY,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  ai_count INTEGER NOT NULL DEFAULT 0,
  terminal_count INTEGER NOT NULL DEFAULT 0,
  country TEXT NOT NULL DEFAULT '',
  country_code TEXT NOT NULL DEFAULT '',
  region TEXT NOT NULL DEFAULT '',
  city TEXT NOT NULL DEFAULT '',
  org TEXT NOT NULL DEFAULT '',
  asn TEXT NOT NULL DEFAULT '',
  isp TEXT NOT NULL DEFAULT '',
  geo TEXT NOT NULL DEFAULT 'pending',
  last_method TEXT NOT NULL DEFAULT '',
  last_path TEXT NOT NULL DEFAULT '',
  last_ua TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ips_last ON ips(last_seen);
`

type Event struct {
	ID          int64       `json:"id"`
	TS          int64       `json:"ts"`
	IP          string      `json:"ip"`
	Kind        string      `json:"kind"`
	Method      string      `json:"method"`
	Scheme      string      `json:"scheme"`
	Host        string      `json:"host"`
	Path        string      `json:"path"`
	Proto       string      `json:"proto"`
	ReqHeaders  http.Header `json:"req_headers,omitempty"`
	ReqBody     string      `json:"req_body"`
	Status      int         `json:"status"`
	RespHeaders http.Header `json:"resp_headers,omitempty"`
	RespBody    string      `json:"resp_body"`
	Source      string      `json:"source"`
	Model       string      `json:"model"`
	LatencyMS   int64       `json:"latency_ms"`
	Tokens      int         `json:"tokens"`
	Session     string      `json:"session"`
	Cmd         string      `json:"cmd"`
	Cwd         string      `json:"cwd"`
	UserAgent   string      `json:"user_agent"`
}

// Summary strips the heavy fields for list/stream use.
func (e Event) Summary() Event {
	e.ReqHeaders, e.RespHeaders = nil, nil
	e.ReqBody, e.RespBody = "", ""
	return e
}

type IPInfo struct {
	IP            string `json:"ip"`
	FirstSeen     int64  `json:"first_seen"`
	LastSeen      int64  `json:"last_seen"`
	Count         int64  `json:"count"`
	AICount       int64  `json:"ai_count"`
	TerminalCount int64  `json:"terminal_count"`
	Country       string `json:"country"`
	CountryCode   string `json:"country_code"`
	Region        string `json:"region"`
	City          string `json:"city"`
	Org           string `json:"org"`
	ASN           string `json:"asn"`
	ISP           string `json:"isp"`
	Geo           string `json:"geo"`
	LastMethod    string `json:"last_method"`
	LastPath      string `json:"last_path"`
	LastUA        string `json:"last_ua"`
}

type Store struct {
	db *sql.DB
}

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: serialize access, avoids SQLITE_BUSY entirely
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func headerJSON(h http.Header) string {
	if h == nil {
		return "{}"
	}
	b, _ := json.Marshal(h)
	return string(b)
}

// InsertEvent stores the event and updates the per-IP aggregate.
// Returns the updated IPInfo and whether the IP is new.
func (s *Store) InsertEvent(e *Event) (IPInfo, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return IPInfo{}, false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO events (ts, ip, kind, method, scheme, host, path, proto, req_headers, req_body, status,
		resp_headers, resp_body, source, model, latency_ms, tokens, session, cmd, cwd, user_agent)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.TS, e.IP, e.Kind, e.Method, e.Scheme, e.Host, e.Path, e.Proto, headerJSON(e.ReqHeaders), e.ReqBody, e.Status,
		headerJSON(e.RespHeaders), e.RespBody, e.Source, e.Model, e.LatencyMS, e.Tokens, e.Session, e.Cmd, e.Cwd, e.UserAgent)
	if err != nil {
		return IPInfo{}, false, err
	}
	e.ID, _ = res.LastInsertId()

	ai := 0
	if e.Source == "ai" {
		ai = 1
	}
	term := 0
	if e.Kind == "terminal" {
		term = 1
	}
	lastPath := e.Path
	if e.Kind == "terminal" {
		lastPath = "$ " + e.Cmd
	}
	var existing int
	_ = tx.QueryRow(`SELECT COUNT(*) FROM ips WHERE ip=?`, e.IP).Scan(&existing)
	if _, err := tx.Exec(`INSERT INTO ips (ip, first_seen, last_seen, count, ai_count, terminal_count, last_method, last_path, last_ua)
		VALUES (?,?,?,1,?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen, count=count+1, ai_count=ai_count+excluded.ai_count,
		terminal_count=terminal_count+excluded.terminal_count, last_method=excluded.last_method, last_path=excluded.last_path,
		last_ua=CASE WHEN excluded.last_ua<>'' THEN excluded.last_ua ELSE last_ua END`,
		e.IP, e.TS, e.TS, ai, term, e.Method, truncate(lastPath, 300), truncate(e.UserAgent, 300)); err != nil {
		return IPInfo{}, false, err
	}
	info, err := scanIP(tx.QueryRow(`SELECT `+ipCols+` FROM ips WHERE ip=?`, e.IP))
	if err != nil {
		return IPInfo{}, false, err
	}
	return info, existing == 0, tx.Commit()
}

const ipCols = `ip, first_seen, last_seen, count, ai_count, terminal_count, country, country_code, region, city, org, asn, isp, geo, last_method, last_path, last_ua`

type scanner interface{ Scan(dest ...any) error }

func scanIP(r scanner) (IPInfo, error) {
	var i IPInfo
	err := r.Scan(&i.IP, &i.FirstSeen, &i.LastSeen, &i.Count, &i.AICount, &i.TerminalCount, &i.Country, &i.CountryCode,
		&i.Region, &i.City, &i.Org, &i.ASN, &i.ISP, &i.Geo, &i.LastMethod, &i.LastPath, &i.LastUA)
	return i, err
}

func (s *Store) SetGeo(ip string, g IPInfo) (IPInfo, error) {
	if _, err := s.db.Exec(`UPDATE ips SET country=?, country_code=?, region=?, city=?, org=?, asn=?, isp=?, geo=? WHERE ip=?`,
		g.Country, g.CountryCode, g.Region, g.City, g.Org, g.ASN, g.ISP, g.Geo, ip); err != nil {
		return IPInfo{}, err
	}
	return s.GetIP(ip)
}

func (s *Store) GetIP(ip string) (IPInfo, error) {
	return scanIP(s.db.QueryRow(`SELECT `+ipCols+` FROM ips WHERE ip=?`, ip))
}

func (s *Store) ListIPs(q string, limit int) ([]IPInfo, error) {
	query := `SELECT ` + ipCols + ` FROM ips`
	var args []any
	if q = strings.TrimSpace(q); q != "" {
		like := "%" + strings.NewReplacer("%", `\%`, "_", `\_`).Replace(q) + "%"
		query += ` WHERE ip LIKE ? ESCAPE '\' OR country LIKE ? ESCAPE '\' OR city LIKE ? ESCAPE '\' OR org LIKE ? ESCAPE '\' OR isp LIKE ? ESCAPE '\' OR asn LIKE ? ESCAPE '\'`
		args = []any{like, like, like, like, like, like}
	}
	query += ` ORDER BY last_seen DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPInfo{}
	for rows.Next() {
		i, err := scanIP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

const eventCols = `id, ts, ip, kind, method, scheme, host, path, proto, req_headers, req_body, status, resp_headers, resp_body,
	source, model, latency_ms, tokens, session, cmd, cwd, user_agent`

func scanEvent(r scanner) (Event, error) {
	var e Event
	var rh, sh string
	err := r.Scan(&e.ID, &e.TS, &e.IP, &e.Kind, &e.Method, &e.Scheme, &e.Host, &e.Path, &e.Proto, &rh, &e.ReqBody, &e.Status,
		&sh, &e.RespBody, &e.Source, &e.Model, &e.LatencyMS, &e.Tokens, &e.Session, &e.Cmd, &e.Cwd, &e.UserAgent)
	if err != nil {
		return e, err
	}
	_ = json.Unmarshal([]byte(rh), &e.ReqHeaders)
	_ = json.Unmarshal([]byte(sh), &e.RespHeaders)
	return e, nil
}

func (s *Store) queryEvents(query string, args ...any) ([]Event, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// EventsForIP returns events newest first, older than beforeID (0 = newest).
func (s *Store) EventsForIP(ip string, beforeID int64, limit int) ([]Event, error) {
	if beforeID <= 0 {
		beforeID = 1 << 62
	}
	return s.queryEvents(`SELECT `+eventCols+` FROM events WHERE ip=? AND id<? ORDER BY id DESC LIMIT ?`, ip, beforeID, limit)
}

func (s *Store) GetEvent(id int64) (Event, error) {
	return scanEvent(s.db.QueryRow(`SELECT `+eventCols+` FROM events WHERE id=?`, id))
}

// RecentHTTPForIP returns the last n AI-answered HTTP events of an IP, oldest first (LLM consistency context).
func (s *Store) RecentHTTPForIP(ip string, n int) ([]Event, error) {
	ev, err := s.queryEvents(`SELECT `+eventCols+` FROM events WHERE ip=? AND kind='http' AND source='ai' ORDER BY id DESC LIMIT ?`, ip, n)
	for i, j := 0, len(ev)-1; i < j; i, j = i+1, j-1 {
		ev[i], ev[j] = ev[j], ev[i]
	}
	return ev, err
}

// TerminalHistory returns the last n terminal commands of a session (only the fields the shell needs), oldest first.
func (s *Store) TerminalHistory(session string, n int) ([]Event, error) {
	rows, err := s.db.Query(`SELECT cmd, cwd, resp_headers, resp_body FROM
		(SELECT id, cmd, cwd, resp_headers, resp_body FROM events WHERE session=? AND kind='terminal' ORDER BY id DESC LIMIT ?)
		ORDER BY id ASC`, session, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var rh string
		if err := rows.Scan(&e.Cmd, &e.Cwd, &rh, &e.RespBody); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(rh), &e.RespHeaders)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Prune enforces retention: events older than maxAge, and the oldest beyond maxEvents.
func (s *Store) Prune(maxAge time.Duration, maxEvents int) (int64, error) {
	cut := time.Now().Add(-maxAge).UnixMilli()
	res, err := s.db.Exec(`DELETE FROM events WHERE ts < ? OR id <= (SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?)`, cut, maxEvents)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		_, err = s.db.Exec(`DELETE FROM ips WHERE ip NOT IN (SELECT DISTINCT ip FROM events)`)
	}
	return n, err
}

type Stats struct {
	EventsTotal     int64 `json:"events_total"`
	Events24h       int64 `json:"events_24h"`
	IPsTotal        int64 `json:"ips_total"`
	IPs24h          int64 `json:"ips_24h"`
	AICalls24h      int64 `json:"ai_calls_24h"`
	TerminalCmds24h int64 `json:"terminal_cmds_24h"`
	AIEnabled       bool  `json:"ai_enabled"`
	AIReady         bool  `json:"ai_ready"`
}

func (s *Store) Stats() (Stats, error) {
	var st Stats
	day := time.Now().Add(-24 * time.Hour).UnixMilli()
	err := s.db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM events),
		(SELECT COUNT(*) FROM events WHERE ts>=?),
		(SELECT COUNT(*) FROM ips),
		(SELECT COUNT(*) FROM ips WHERE last_seen>=?),
		(SELECT COUNT(*) FROM events WHERE ts>=? AND source='ai'),
		(SELECT COUNT(*) FROM events WHERE ts>=? AND kind='terminal')`, day, day, day, day).
		Scan(&st.EventsTotal, &st.Events24h, &st.IPsTotal, &st.IPs24h, &st.AICalls24h, &st.TerminalCmds24h)
	return st, err
}

func (s *Store) Clear() error {
	_, err := s.db.Exec(`DELETE FROM events; DELETE FROM ips; DELETE FROM sqlite_sequence WHERE name='events';`)
	if err == nil {
		_, _ = s.db.Exec(`VACUUM`)
		_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	}
	return err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// avoid cutting in the middle of a UTF-8 sequence
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
