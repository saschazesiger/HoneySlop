package main

// Realistic MySQL 5.7 server + mysql/mysqldump client emulation backed by an
// in-memory SQLite engine (modernc.org/sqlite). The world (world.go) holds the
// real generated credentials and data; this file renders a believable MySQL
// surface on top of it: authentication, privilege checks, MySQL error codes,
// SHOW/USE/DESCRIBE, a synthesized information_schema and the client banners.
//
// Scope note: this module deliberately targets realistic *normal* client and
// privilege behaviour. Unsupported / exotic syntax returns a generic MySQL
// 1064 syntax error rather than attempting a full MySQL->SQLite dialect
// rewrite.

import (
	"database/sql/driver"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	sqlite "modernc.org/sqlite"
)

// ---- fixed server identity (matches the fictional company in world.go) ----

const (
	mysqlServerVersion   = worldMySQLVer // "5.7.42-0ubuntu0.18.04.1-log"
	mysqlClientVersion   = "8.0.35-0ubuntu0.20.04.1"
	mysqlServerHostFQDN  = worldDBHost // db-prod-01.internal.veltrona-group.com
	mysqlServerHostShort = "db-prod-01"
	mysqlServerIP        = worldDBIP   // 10.20.4.11
	mysqlClientIP        = worldHostIP // client host as seen by the server: 10.20.2.43
	mysqlPort            = 3306
	mysqlSocket          = "/var/run/mysqld/mysqld.sock"
	mysqlDataDir         = "/var/lib/mysql/"
	mysqlBaseDir         = "/usr/"

	maxResultRows  = 1000
	maxResultBytes = 64 * 1024
	maxStmtLen     = 256 * 1024
	maxDumpBytes   = 200 * 1024
	queryTimeout   = 3 * time.Second
	maxSessions    = 200
)

// MySQLError is a MySQL-protocol error (code + SQLSTATE + message).
type MySQLError struct {
	Code  int
	State string
	Msg   string
}

func (e *MySQLError) Error() string {
	return fmt.Sprintf("ERROR %d (%s): %s", e.Code, e.State, e.Msg)
}

func myErr(code int, state, format string, a ...any) *MySQLError {
	return &MySQLError{Code: code, State: state, Msg: fmt.Sprintf(format, a...)}
}

// myErrLit builds an error whose message is used verbatim (may contain %).
func myErrLit(code int, state, msg string) *MySQLError {
	return &MySQLError{Code: code, State: state, Msg: msg}
}

// SQLResult is one statement's result (a result set or an OK packet).
type SQLResult struct {
	Columns  []string
	Rows     [][]*string // nil = NULL
	Affected int64
	Info     string
	IsSet    bool
	Elapsed  time.Duration
}

// MySQLServer renders the MySQL surface over the world data.
type MySQLServer struct {
	w *World

	mu       sync.Mutex
	sessions map[string]*mysqlInstance // terminal per-session writable copies
	order    []string                  // LRU order of session ids
	web      map[string]*mysqlInstance // per-account shared snapshots for the web view
}

// NewMySQLServer builds a server bound to world w.
func NewMySQLServer(w *World) *MySQLServer {
	registerMySQLFuncs()
	return &MySQLServer{
		w:        w,
		sessions: map[string]*mysqlInstance{},
		web:      map[string]*mysqlInstance{},
	}
}

// ---- account visibility ----

// account looks up a MySQL account by user name (host is not matched here; the
// world only ever has one row per user for this honeypot).
func (s *MySQLServer) account(user string) *MySQLAccount {
	if s.w == nil || s.w.MySQL == nil {
		return nil
	}
	return s.w.MySQL[user]
}

// systemSchemas are always-present server schemas not stored in w.dbs.
var systemSchemas = []string{"information_schema", "performance_schema", "sys"}

// canUseSchema reports whether the account may reference a given schema.
func canUseSchema(a *MySQLAccount, schema string) bool {
	schema = strings.ToLower(schema)
	if schema == "information_schema" {
		return true // MySQL always grants USAGE-level access to information_schema
	}
	if a == nil {
		return false
	}
	allAccess := false
	for _, d := range a.DBs {
		if d == "*" {
			allAccess = true
			break
		}
		if strings.EqualFold(d, schema) {
			return true
		}
	}
	if !allAccess {
		return false
	}
	// "*" accounts (root, backup) may also see the server system schemas.
	switch schema {
	case "performance_schema", "sys", "mysql":
		return true
	}
	return true
}

// visibleSchemas returns the schemas the account may see, in SHOW DATABASES order.
func (s *MySQLServer) visibleSchemas(a *MySQLAccount) []string {
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if n == "" || seen[strings.ToLower(n)] {
			return
		}
		if canUseSchema(a, n) {
			seen[strings.ToLower(n)] = true
			out = append(out, n)
		}
	}
	// information_schema first (MySQL lists it first).
	add("information_schema")
	for _, sys := range []string{"performance_schema", "sys", "mysql"} {
		add(sys)
	}
	for _, d := range s.w.dbs {
		add(d.Name)
	}
	// Order like real MySQL: information_schema, then the rest alphabetically.
	rest := out[1:]
	sort.Slice(rest, func(i, j int) bool { return rest[i] < rest[j] })
	return out
}

// findDB returns the Database definition for a schema name (nil if not a data schema).
func (s *MySQLServer) findDB(name string) *Database {
	for i := range s.w.dbs {
		if strings.EqualFold(s.w.dbs[i].Name, name) {
			return &s.w.dbs[i]
		}
	}
	return nil
}

func (s *MySQLServer) schemaExists(name string) bool {
	switch strings.ToLower(name) {
	case "information_schema", "performance_schema", "sys":
		return true
	}
	return s.findDB(name) != nil
}

// ---- global SQLite function registration (MySQL builtins SQLite lacks) ----

var funcOnce sync.Once

func registerMySQLFuncs() {
	funcOnce.Do(func() {
		reg := func(name string, nArg int32, fn func(args []any) (any, error)) {
			_ = sqlite.RegisterScalarFunction(name, nArg, func(_ *sqlite.FunctionContext, raw []driver.Value) (driver.Value, error) {
				in := make([]any, len(raw))
				for i, v := range raw {
					in[i] = v
				}
				out, err := fn(in)
				if err != nil {
					return nil, err
				}
				return out, nil
			})
		}
		reg("concat", -1, fnConcat)
		reg("concat_ws", -1, fnConcatWS)
		reg("if", 3, fnIf)
		reg("left", 2, fnLeft)
		reg("right", 2, fnRight)
		reg("mid", 3, fnSubstr3)
		reg("md5", 1, fnMD5)
		reg("sha1", 1, fnSHA1)
		reg("now", 0, func(_ []any) (any, error) { return time.Now().Format("2006-01-02 15:04:05"), nil })
		reg("curdate", 0, func(_ []any) (any, error) { return time.Now().Format("2006-01-02"), nil })
		reg("version", 0, func(_ []any) (any, error) { return mysqlServerVersion, nil })
	})
}
