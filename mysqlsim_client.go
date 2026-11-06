package main

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// MySQLClient is the serializable state of an interactive mysql monitor session.
type MySQLClient struct {
	User string `json:"user"`
	DB   string `json:"db"`
	Host string `json:"host"`
	Buf  string `json:"buf,omitempty"`
}

// MySQLPending records a client invocation waiting for a hidden password prompt.
type MySQLPending struct {
	Prog string   `json:"prog"`
	Argv []string `json:"argv"`
}

// MySQLRun is the result of an Invoke/Continue call.
type MySQLRun struct {
	Output       string
	NeedPassword bool
	Pending      *MySQLPending
	Interactive  *MySQLClient
	Authed       string
}

// ---- option parsing ----

type mysqlOpts struct {
	user       string
	host       string
	database   string
	port       int
	password   string
	hasUser    bool
	hasHost    bool
	wantPass   bool // -p / --password seen
	inlinePass bool // password value given on the command line
	execute    string
	hasExecute bool
	batch      bool
	skipCols   bool
	vertical   bool
	table      bool
	silent     bool
	showVer    bool
	showHelp   bool
	protocol   string
	positional []string
	badOption  string

	// mysqldump-specific
	allDatabases bool
	databasesSet bool
	noData       bool
}

// valueOpts are short options that consume a value.
func parseMySQLArgs(argv []string) *mysqlOpts {
	o := &mysqlOpts{port: 3306}
	takeVal := func(cur string, i *int) string {
		if cur != "" {
			return cur
		}
		if *i+1 < len(argv) {
			*i++
			return argv[*i]
		}
		return ""
	}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			o.positional = append(o.positional, argv[i+1:]...)
			i = len(argv)
		case strings.HasPrefix(a, "--"):
			name, val, hasEq := strings.Cut(a[2:], "=")
			switch name {
			case "user":
				o.user, o.hasUser = valOrNext(val, hasEq, argv, &i), true
			case "host":
				o.host, o.hasHost = valOrNext(val, hasEq, argv, &i), true
			case "database":
				o.database = valOrNext(val, hasEq, argv, &i)
			case "port":
				o.port = atoiDefault(valOrNext(val, hasEq, argv, &i), 3306)
			case "password":
				o.wantPass = true
				if hasEq {
					o.password, o.inlinePass = val, true
				}
			case "execute":
				o.execute, o.hasExecute = valOrNext(val, hasEq, argv, &i), true
			case "protocol":
				o.protocol = valOrNext(val, hasEq, argv, &i)
			case "batch":
				o.batch = true
			case "skip-column-names":
				o.skipCols = true
			case "vertical":
				o.vertical = true
			case "table":
				o.table = true
			case "silent":
				o.silent = true
			case "version":
				o.showVer = true
			case "help":
				o.showHelp = true
			case "all-databases":
				o.allDatabases = true
			case "databases":
				o.databasesSet = true
			case "no-data":
				o.noData = true
			default:
				// Many mysqldump flags (--single-transaction, --routines, ...)
				// are accepted as no-ops rather than erroring.
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			// grouped short options, getopt-style
			j := 1
			for j < len(a) {
				c := a[j]
				rest := a[j+1:]
				switch c {
				case 'u':
					o.user, o.hasUser = takeVal(rest, &i), true
					j = len(a)
				case 'h':
					o.host, o.hasHost = takeVal(rest, &i), true
					j = len(a)
				case 'D':
					o.database = takeVal(rest, &i)
					j = len(a)
				case 'P':
					o.port = atoiDefault(takeVal(rest, &i), 3306)
					j = len(a)
				case 'e':
					o.execute, o.hasExecute = takeVal(rest, &i), true
					j = len(a)
				case 'p':
					o.wantPass = true
					if rest != "" {
						o.password, o.inlinePass = rest, true
					}
					j = len(a)
				case 'B':
					o.batch = true
					j++
				case 'N':
					o.skipCols = true
					j++
				case 'E':
					o.vertical = true
					j++
				case 't':
					o.table = true
					j++
				case 's':
					o.silent = true
					j++
				case 'V':
					o.showVer = true
					j++
				case 'A':
					o.allDatabases = true
					j++
				case '?':
					o.showHelp = true
					j++
				default:
					o.badOption = "-" + string(c)
					j++
				}
			}
		default:
			o.positional = append(o.positional, a)
		}
	}
	return o
}

func valOrNext(val string, hasEq bool, argv []string, i *int) string {
	if hasEq {
		return val
	}
	if *i+1 < len(argv) {
		*i++
		return argv[*i]
	}
	return ""
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

// ---- public entry points ----

func (s *MySQLServer) Invoke(ctx context.Context, sid, prog string, argv []string, localUser, stdin string) MySQLRun {
	return s.runClient(ctx, sid, prog, argv, localUser, stdin, nil)
}

func (s *MySQLServer) Continue(ctx context.Context, sid string, p MySQLPending, localUser, password string) MySQLRun {
	return s.runClient(ctx, sid, p.Prog, p.Argv, localUser, "", &password)
}

func (s *MySQLServer) runClient(ctx context.Context, sid, prog string, argv []string, localUser, stdin string, supplied *string) MySQLRun {
	o := parseMySQLArgs(argv)
	var out strings.Builder

	if o.showVer {
		out.WriteString(clientVersionLine() + "\n")
		return MySQLRun{Output: out.String()}
	}
	if o.showHelp {
		out.WriteString(clientHelp(prog))
		return MySQLRun{Output: out.String()}
	}

	// Resolve user and the /root/.my.cnf shortcut.
	user := o.user
	usedMyCnf := false
	if !o.hasUser {
		user = localUser
	}
	if user == "" {
		user = localUser
	}

	// Determine the password.
	var password string
	usingPassword := false
	switch {
	case supplied != nil:
		password, usingPassword = *supplied, true
	case o.inlinePass:
		password, usingPassword = o.password, true
		out.WriteString("mysql: [Warning] Using a password on the command line interface can be insecure.\n")
	case o.wantPass:
		// -p / --password with no value: prompt for it (hidden).
		return MySQLRun{NeedPassword: true, Pending: &MySQLPending{Prog: prog, Argv: argv}}
	default:
		// No password option. For local root, read /root/.my.cnf.
		if localUser == "root" && !o.hasUser {
			if a := s.account("root"); a != nil {
				user = "root"
				password, usingPassword = a.Password, true
				usedMyCnf = true
				if !o.hasHost {
					o.host, o.hasHost = mysqlServerHostFQDN, true
				}
			}
		}
	}

	// Connectivity: resolve the target host.
	if msg, ok := s.hostError(o, usedMyCnf); !ok {
		out.WriteString(msg + "\n")
		return MySQLRun{Output: out.String()}
	}

	// Authenticate.
	acct, ok := s.w.CheckMySQL(user, password)
	if !ok {
		up := "NO"
		if usingPassword {
			up = "YES"
		}
		out.WriteString(fmt.Sprintf("ERROR 1045 (28000): Access denied for user '%s'@'%s' (using password: %s)\n", user, mysqlClientIP, up))
		return MySQLRun{Output: out.String()}
	}
	authed := user

	// Select the starting database (option or trailing positional for mysql).
	db := o.database
	if db == "" && prog == "mysql" && len(o.positional) > 0 {
		db = o.positional[0]
	}
	if db != "" {
		if !s.schemaExists(db) {
			out.WriteString(fmt.Sprintf("ERROR 1049 (42000): Unknown database '%s'\n", db))
			return MySQLRun{Output: out.String(), Authed: authed}
		}
		if !canUseSchema(acct, db) {
			out.WriteString(fmt.Sprintf("ERROR 1044 (42000): Access denied for user '%s'@'%s' to database '%s'\n", user, mysqlClientIP, db))
			return MySQLRun{Output: out.String(), Authed: authed}
		}
		db = canonicalSchema(s, db)
	}

	if prog == "mysqldump" {
		dump := s.runDump(ctx, sid, o, acct, user, db)
		out.WriteString(dump)
		return MySQLRun{Output: out.String(), Authed: authed}
	}

	// Batch mode: -e or piped stdin.
	batchSQL := ""
	if o.hasExecute {
		batchSQL = o.execute
	} else if stdin != "" {
		batchSQL = stdin
	}
	if batchSQL != "" {
		inst, err := s.getSessionInstance(sid, acct, mysqlClientIP)
		if err != nil {
			out.WriteString("ERROR 1105 (HY000): Unknown error\n")
			return MySQLRun{Output: out.String(), Authed: authed}
		}
		ec := &execCtx{srv: s, inst: inst, acct: acct, user: user, host: mysqlClientIP, curDB: db}
		tab := o.batch || (stdin != "" && !o.table)
		out.WriteString(s.runBatch(ctx, ec, batchSQL, o, tab))
		return MySQLRun{Output: out.String(), Authed: authed}
	}

	// Interactive monitor.
	// Prime the session instance so writes persist across lines.
	if _, err := s.getSessionInstance(sid, acct, mysqlClientIP); err != nil {
		out.WriteString("ERROR 1105 (HY000): Unknown error\n")
		return MySQLRun{Output: out.String(), Authed: authed}
	}
	out.WriteString(interactiveBanner())
	cl := &MySQLClient{User: user, DB: db, Host: mysqlClientIP}
	return MySQLRun{Output: out.String(), Interactive: cl, Authed: authed}
}

var ipRe = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)

// hostError validates connectivity to the requested host. ok=false => error message.
func (s *MySQLServer) hostError(o *mysqlOpts, usedMyCnf bool) (string, bool) {
	host := o.host
	if !o.hasHost || host == "" {
		// No -h: the mysql client uses the local UNIX socket. There is no
		// local mysqld on this web host.
		return fmt.Sprintf("ERROR 2002 (HY000): Can't connect to local MySQL server through socket '%s' (2)", mysqlSocket), false
	}
	switch strings.ToLower(host) {
	case "localhost":
		return fmt.Sprintf("ERROR 2002 (HY000): Can't connect to local MySQL server through socket '%s' (2)", mysqlSocket), false
	case strings.ToLower(mysqlServerHostFQDN), mysqlServerHostShort, mysqlServerIP:
		return "", true
	}
	if ipRe.MatchString(host) {
		if host == mysqlServerIP {
			return "", true
		}
		return fmt.Sprintf("ERROR 2003 (HY000): Can't connect to MySQL server on '%s' (110)", host), false
	}
	// Unresolvable hostname.
	return fmt.Sprintf("ERROR 2005 (HY000): Unknown MySQL server host '%s' (-2)", host), false
}

// ---- batch execution ----

func (s *MySQLServer) runBatch(ctx context.Context, ec *execCtx, script string, o *mysqlOpts, tab bool) string {
	var out strings.Builder
	for _, stmt := range splitStatements(script) {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		res, me := ec.runStatement(ctx, stmt)
		if me != nil {
			out.WriteString(me.Error() + "\n")
			continue
		}
		if res == nil || !res.IsSet {
			continue // OK packet: batch mode is silent for non-result statements
		}
		switch {
		case o.vertical:
			out.WriteString(formatVertical(res))
		case tab:
			out.WriteString(formatTab(res, o.skipCols))
		default:
			out.WriteString(FormatMySQLTable(res))
		}
	}
	return out.String()
}

func formatTab(r *SQLResult, skipCols bool) string {
	var b strings.Builder
	if !skipCols {
		b.WriteString(strings.Join(r.Columns, "\t"))
		b.WriteByte('\n')
	}
	for _, row := range r.Rows {
		cells := make([]string, len(row))
		for i, c := range row {
			if c == nil {
				cells[i] = "NULL"
			} else {
				cells[i] = *c
			}
		}
		b.WriteString(strings.Join(cells, "\t"))
		b.WriteByte('\n')
	}
	return b.String()
}

func formatVertical(r *SQLResult) string {
	var b strings.Builder
	w := 0
	for _, c := range r.Columns {
		if len(c) > w {
			w = len(c)
		}
	}
	for i, row := range r.Rows {
		fmt.Fprintf(&b, "*************************** %d. row ***************************\n", i+1)
		for j, col := range r.Columns {
			val := "NULL"
			if j < len(row) && row[j] != nil {
				val = *row[j]
			}
			fmt.Fprintf(&b, "%*s: %s\n", w, col, val)
		}
	}
	return b.String()
}
