package main

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// execCtx carries the mutable state of a connection while it runs statements.
type execCtx struct {
	srv      *MySQLServer
	inst     *mysqlInstance
	acct     *MySQLAccount
	user     string
	host     string
	curDB    string // current database ("" = none selected)
	rollback bool   // web view: writes run in a rolled-back transaction
}

// identifier of the connection for user()/current_user() style functions.
func (ec *execCtx) ident() string { return ec.user + "@" + ec.host }

// runStatement executes a single (already split) statement.
func (ec *execCtx) runStatement(ctx context.Context, stmt string) (*SQLResult, *MySQLError) {
	start := time.Now()
	q := strings.TrimSpace(stmt)
	q = strings.TrimRight(q, ";")
	q = strings.TrimSpace(q)
	if q == "" {
		return &SQLResult{}, nil
	}
	if len(q) > maxStmtLen {
		return nil, myErr(1064, "42000", "Query length exceeds server limit")
	}
	kw := firstKeyword(q)

	// Client/meta handling that never reaches SQLite.
	switch kw {
	case "use":
		return ec.doUse(q, start)
	case "show":
		return ec.doShow(ctx, q, start)
	case "describe", "desc", "explain":
		return ec.doDescribe(q, start)
	case "set":
		// SET session/names/autocommit/... -> accept silently like MySQL.
		return &SQLResult{Affected: 0, Elapsed: time.Since(start)}, nil
	}

	// Special informational SELECTs answered without the SQLite engine.
	if r := ec.specialSelect(q, start); r != nil {
		return r, nil
	}

	// Privilege and "no database selected" checks.
	if me := ec.checkPrivileges(kw, q); me != nil {
		return nil, me
	}

	// Rewrite MySQL-isms that SQLite does not understand.
	rq := ec.rewrite(q)

	if isWrite(kw) {
		return ec.execWrite(ctx, kw, rq, start)
	}
	return ec.execQuery(ctx, rq, start)
}

// ---- USE ----

func (ec *execCtx) doUse(q string, start time.Time) (*SQLResult, *MySQLError) {
	name := strings.TrimSpace(q[len("use"):])
	name = strings.Trim(name, "`\"' ")
	if name == "" {
		return nil, myErrLit(1064, "42000", syntaxNear(""))
	}
	if !ec.srv.schemaExists(name) {
		return nil, myErr(1049, "42000", "Unknown database '%s'", name)
	}
	if !canUseSchema(ec.acct, name) {
		return nil, myErr(1044, "42000", "Access denied for user '%s'@'%s' to database '%s'", ec.user, ec.host, name)
	}
	ec.curDB = canonicalSchema(ec.srv, name)
	return &SQLResult{Info: "Database changed", Elapsed: time.Since(start)}, nil
}

func canonicalSchema(s *MySQLServer, name string) string {
	for _, sys := range systemSchemas {
		if strings.EqualFold(sys, name) {
			return sys
		}
	}
	if strings.EqualFold(name, "mysql") {
		return "mysql"
	}
	if d := s.findDB(name); d != nil {
		return d.Name
	}
	return name
}

// ---- DESCRIBE / DESC ----

var descCols = []string{"Field", "Type", "Null", "Key", "Default", "Extra"}

func (ec *execCtx) doDescribe(q string, start time.Time) (*SQLResult, *MySQLError) {
	rest := strings.TrimSpace(q[len(firstKeyword(q)):])
	schema, table := ec.resolveTable(rest)
	if schema == "" {
		return nil, myErr(1046, "3D000", "No database selected")
	}
	d := ec.srv.findDB(schema)
	if d == nil || !canUseSchema(ec.acct, schema) {
		return nil, myErr(1146, "42S02", "Table '%s.%s' doesn't exist", schema, table)
	}
	tbl := findTable(d, table)
	if tbl == nil {
		return nil, myErr(1146, "42S02", "Table '%s.%s' doesn't exist", schema, table)
	}
	res := &SQLResult{Columns: descCols, IsSet: true, Elapsed: time.Since(start)}
	for _, c := range tbl.Columns {
		null := "NO"
		if c.Nullable {
			null = "YES"
		}
		res.Rows = append(res.Rows, []*string{sp(c.Name), sp(c.Type), sp(null), sp(c.Key), c.Default, sp(c.Extra)})
	}
	return res, nil
}

// ---- privilege checks ----

var schemaQualRe = regexp.MustCompile(`(?i)\b([A-Za-z_][A-Za-z0-9_$]*)\s*\.\s*` + "`?" + `[A-Za-z_][A-Za-z0-9_$]*`)

func (ec *execCtx) checkPrivileges(kw, q string) *MySQLError {
	write := isWrite(kw)
	cmd := strings.ToUpper(kw)
	// Read-only account attempting a write.
	if write && ec.acct != nil && ec.acct.ReadOnly {
		return myErr(1142, "42000", "%s command denied to user '%s'@'%s' for table '%s'",
			cmd, ec.user, ec.host, firstTableName(q))
	}
	// Schemas referenced via explicit db.table qualifier.
	refs := map[string]bool{}
	for _, m := range schemaQualRe.FindAllStringSubmatch(q, -1) {
		sc := m[1]
		if isSchemaKeyword(sc) {
			continue
		}
		refs[sc] = true
	}
	for sc := range refs {
		if !ec.srv.schemaExists(sc) {
			continue // let the engine report 1146 for a bad name
		}
		if !canUseSchema(ec.acct, sc) {
			return myErr(1142, "42000", "%s command denied to user '%s'@'%s' for table '%s'",
				cmdForDenied(write, kw), ec.user, ec.host, firstTableName(q))
		}
	}
	// Unqualified table reference with no current database.
	if ec.curDB == "" && referencesTable(q) && len(refs) == 0 {
		return myErr(1046, "3D000", "No database selected")
	}
	return nil
}

func cmdForDenied(write bool, kw string) string {
	if write {
		return strings.ToUpper(kw)
	}
	return "SELECT"
}

// ---- rewrite MySQL-isms -> SQLite ----

var (
	atVarRe     = regexp.MustCompile(`(?i)@@(global\.|session\.|local\.)?([A-Za-z_][A-Za-z0-9_]*)`)
	fnCurUser   = regexp.MustCompile(`(?i)\b(current_user|system_user|session_user|user)\s*\(\s*\)`)
	fnDB        = regexp.MustCompile(`(?i)\b(database|schema)\s*\(\s*\)`)
	bareCurUser = regexp.MustCompile(`(?i)\bcurrent_user\b`)
)

func (ec *execCtx) rewrite(q string) string {
	q = atVarRe.ReplaceAllStringFunc(q, func(m string) string {
		sm := atVarRe.FindStringSubmatch(m)
		return sqlQuote(ec.systemVar(strings.ToLower(sm[2])))
	})
	q = fnCurUser.ReplaceAllString(q, sqlQuote(ec.ident()))
	q = fnDB.ReplaceAllStringFunc(q, func(string) string {
		if ec.curDB == "" {
			return "NULL"
		}
		return sqlQuote(ec.curDB)
	})
	// bare CURRENT_USER (no parens); the ()-form was already replaced above.
	q = bareCurUser.ReplaceAllString(q, sqlQuote(ec.ident()))
	return q
}

func (ec *execCtx) systemVar(name string) string {
	switch name {
	case "version":
		return mysqlServerVersion
	case "version_comment":
		return "MySQL Community Server (GPL)"
	case "hostname":
		return mysqlServerHostShort
	case "datadir":
		return mysqlDataDir
	case "basedir":
		return mysqlBaseDir
	case "secure_file_priv":
		return ""
	case "version_compile_os":
		return "Linux"
	case "version_compile_machine":
		return "x86_64"
	default:
		return ""
	}
}

// ---- special informational SELECTs ----

var simpleSelectRe = regexp.MustCompile(`(?is)^select\s+(.*)$`)

func (ec *execCtx) specialSelect(q string, start time.Time) *SQLResult {
	m := simpleSelectRe.FindStringSubmatch(q)
	if m == nil {
		return nil
	}
	body := strings.TrimSpace(m[1])
	// Only handle single-expression selects with no FROM clause.
	if hasFromClause(body) {
		return nil
	}
	exprs := splitTopLevel(body, ',')
	cols := make([]string, len(exprs))
	vals := make([]*string, len(exprs))
	for i, raw := range exprs {
		expr, alias := splitAlias(raw)
		v, ok := ec.evalSimpleExpr(expr)
		if !ok {
			return nil // not a known informational expression -> hand to engine
		}
		if alias == "" {
			alias = strings.TrimSpace(raw)
		}
		cols[i] = alias
		vals[i] = v
	}
	return &SQLResult{Columns: cols, Rows: [][]*string{vals}, IsSet: true, Elapsed: time.Since(start)}
}

func (ec *execCtx) evalSimpleExpr(expr string) (*string, bool) {
	e := strings.TrimSpace(expr)
	low := strings.ToLower(e)
	switch {
	case low == "version()" || low == "@@version":
		return sp(mysqlServerVersion), true
	case low == "@@version_comment":
		return sp("MySQL Community Server (GPL)"), true
	case low == "@@hostname":
		return sp(mysqlServerHostShort), true
	case low == "@@datadir":
		return sp(mysqlDataDir), true
	case low == "@@basedir":
		return sp(mysqlBaseDir), true
	case low == "@@secure_file_priv":
		return sp(""), true
	case low == "database()" || low == "schema()":
		if ec.curDB == "" {
			return nil, true
		}
		return sp(ec.curDB), true
	case low == "user()" || low == "current_user()" || low == "system_user()" ||
		low == "session_user()" || low == "current_user":
		return sp(ec.ident()), true
	}
	// quoted string literal
	if len(e) >= 2 && (e[0] == '\'' || e[0] == '"') && e[len(e)-1] == e[0] {
		return sp(unquoteSQL(e)), true
	}
	// plain integer / float literal
	if _, err := strconv.ParseFloat(e, 64); err == nil {
		return sp(e), true
	}
	return nil, false
}

// ---- engine execution ----

func (ec *execCtx) execQuery(ctx context.Context, q string, start time.Time) (*SQLResult, *MySQLError) {
	cctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := ec.inst.db.QueryContext(cctx, q)
	if err != nil {
		return nil, ec.mapError(err, q)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, ec.mapError(err, q)
	}
	res := &SQLResult{Columns: cols, IsSet: true}
	bytes := 0
	for rows.Next() {
		holders := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range holders {
			ptrs[i] = &holders[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, ec.mapError(err, q)
		}
		row := make([]*string, len(cols))
		for i := range holders {
			row[i] = rawToStr(holders[i])
			if row[i] != nil {
				bytes += len(*row[i])
			}
		}
		res.Rows = append(res.Rows, row)
		if len(res.Rows) >= maxResultRows || bytes >= maxResultBytes {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, ec.mapError(err, q)
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

func (ec *execCtx) execWrite(ctx context.Context, kw, q string, start time.Time) (*SQLResult, *MySQLError) {
	cctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	var affected int64
	if ec.rollback {
		tx, err := ec.inst.db.BeginTx(cctx, nil)
		if err != nil {
			return nil, ec.mapError(err, q)
		}
		r, err := tx.ExecContext(cctx, q)
		if err != nil {
			tx.Rollback()
			return nil, ec.mapError(err, q)
		}
		affected, _ = r.RowsAffected()
		_ = tx.Rollback() // web writes never persist
	} else {
		r, err := ec.inst.db.ExecContext(cctx, q)
		if err != nil {
			return nil, ec.mapError(err, q)
		}
		affected, _ = r.RowsAffected()
	}
	res := &SQLResult{Affected: affected, Elapsed: time.Since(start)}
	switch kw {
	case "update":
		res.Info = "Rows matched: " + itoa(affected) + "  Changed: " + itoa(affected) + "  Warnings: 0"
	case "insert", "replace":
		if affected > 1 {
			res.Info = "Records: " + itoa(affected) + "  Duplicates: 0  Warnings: 0"
		}
	}
	return res, nil
}

// ---- public web API ----

// Query runs one statement as an account on its shared snapshot (phpMyAdmin).
// Writes are executed then rolled back but reported as success.
func (s *MySQLServer) Query(ctx context.Context, user, db, query string) (*SQLResult, *MySQLError) {
	acct := s.account(user)
	if acct == nil {
		return nil, myErr(1045, "28000", "Access denied for user '%s'@'%s' (using password: YES)", user, mysqlClientIP)
	}
	inst, err := s.getWebInstance(acct, mysqlClientIP)
	if err != nil {
		return nil, myErr(1105, "HY000", "Unknown error")
	}
	ec := &execCtx{srv: s, inst: inst, acct: acct, user: user, host: mysqlClientIP, rollback: true}
	if db != "" {
		if !s.schemaExists(db) {
			return nil, myErr(1049, "42000", "Unknown database '%s'", db)
		}
		if !canUseSchema(acct, db) {
			return nil, myErr(1044, "42000", "Access denied for user '%s'@'%s' to database '%s'", user, mysqlClientIP, db)
		}
		ec.curDB = canonicalSchema(s, db)
	}
	stmts := splitStatements(query)
	var last *SQLResult
	for _, st := range stmts {
		if strings.TrimSpace(st) == "" {
			continue
		}
		r, me := ec.runStatement(ctx, st)
		if me != nil {
			return nil, me
		}
		last = r
	}
	if last == nil {
		last = &SQLResult{}
	}
	return last, nil
}

// Schema returns, for the account, the databases it may see mapped to their tables.
func (s *MySQLServer) Schema(user string) map[string][]string {
	acct := s.account(user)
	out := map[string][]string{}
	for _, sc := range s.visibleSchemas(acct) {
		if d := s.findDB(sc); d != nil {
			names := make([]string, len(d.Tables))
			for i, t := range d.Tables {
				names[i] = t.Name
			}
			out[sc] = names
		} else {
			out[sc] = []string{}
		}
	}
	return out
}
