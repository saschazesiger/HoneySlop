package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// doShow handles the SHOW family of statements.
func (ec *execCtx) doShow(ctx context.Context, q string, start time.Time) (*SQLResult, *MySQLError) {
	rest := strings.TrimSpace(q[len("show"):])
	full := false
	if m := cutPrefixFold(rest, "full "); m != "" {
		full, rest = true, strings.TrimSpace(m)
	}
	low := strings.ToLower(rest)
	switch {
	case low == "databases" || low == "schemas" || strings.HasPrefix(low, "databases ") || strings.HasPrefix(low, "schemas "):
		return ec.showDatabases(rest, start)
	case low == "tables" || strings.HasPrefix(low, "tables"):
		return ec.showTables(rest, full, start)
	case strings.HasPrefix(low, "columns") || strings.HasPrefix(low, "fields"):
		return ec.showColumns(rest, full, start)
	case strings.HasPrefix(low, "create table"):
		return ec.showCreateTable(strings.TrimSpace(rest[len("create table"):]), start)
	case strings.HasPrefix(low, "create database") || strings.HasPrefix(low, "create schema"):
		return ec.showCreateDatabase(rest, start)
	case low == "grants" || strings.HasPrefix(low, "grants"):
		return ec.showGrants(rest, start)
	case strings.HasPrefix(low, "variables"):
		return ec.showVariables(rest, start)
	case strings.HasPrefix(low, "status") || strings.HasPrefix(low, "global status") || strings.HasPrefix(low, "session status"):
		return ec.showStatus(start)
	case strings.HasPrefix(low, "processlist"):
		return ec.showProcesslist(start)
	case strings.HasPrefix(low, "engines"):
		return ec.showEngines(start)
	case strings.HasPrefix(low, "warnings"):
		return &SQLResult{Columns: []string{"Level", "Code", "Message"}, IsSet: true, Elapsed: time.Since(start)}, nil
	case strings.HasPrefix(low, "charset") || strings.HasPrefix(low, "character set"):
		return ec.showCharset(start)
	}
	return nil, myErrLit(1064, "42000", syntaxNear(rest))
}

func (ec *execCtx) showDatabases(rest string, start time.Time) (*SQLResult, *MySQLError) {
	like := parseLike(rest)
	res := &SQLResult{Columns: []string{"Database"}, IsSet: true}
	for _, sc := range ec.srv.visibleSchemas(ec.acct) {
		if like != "" && !likeMatch(like, sc) {
			continue
		}
		res.Rows = append(res.Rows, []*string{sp(sc)})
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

func (ec *execCtx) showTables(rest string, full bool, start time.Time) (*SQLResult, *MySQLError) {
	rest = strings.TrimSpace(rest[len("tables"):])
	schema := ec.curDB
	if from := cutFromClause(&rest); from != "" {
		schema = canonicalSchema(ec.srv, from)
		if !ec.srv.schemaExists(from) {
			return nil, myErr(1049, "42000", "Unknown database '%s'", from)
		}
		if !canUseSchema(ec.acct, from) {
			return nil, myErr(1044, "42000", "Access denied for user '%s'@'%s' to database '%s'", ec.user, ec.host, from)
		}
	}
	if schema == "" {
		return nil, myErr(1046, "3D000", "No database selected")
	}
	like := parseLike(rest)
	col := "Tables_in_" + schema
	cols := []string{col}
	if full {
		cols = append(cols, "Table_type")
	}
	res := &SQLResult{Columns: cols, IsSet: true}
	d := ec.srv.findDB(schema)
	var names []string
	if d != nil {
		for _, t := range d.Tables {
			names = append(names, t.Name)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		if like != "" && !likeMatch(like, n) {
			continue
		}
		row := []*string{sp(n)}
		if full {
			row = append(row, sp("BASE TABLE"))
		}
		res.Rows = append(res.Rows, row)
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

func (ec *execCtx) showColumns(rest string, full bool, start time.Time) (*SQLResult, *MySQLError) {
	rest = strings.TrimSpace(rest[strings.IndexAny(rest, " \t"):])
	// SHOW COLUMNS FROM tbl [FROM db] [LIKE ...]
	rest = strings.TrimSpace(trimPrefixFold(rest, "from "))
	rest = strings.TrimSpace(trimPrefixFold(rest, "in "))
	// first token = table (maybe db.table)
	tableTok, after := firstToken(rest)
	schema, table := ec.resolveTable(tableTok)
	if from := cutFromClause(&after); from != "" {
		schema = canonicalSchema(ec.srv, from)
	}
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
	cols := []string{"Field", "Type", "Null", "Key", "Default", "Extra"}
	if full {
		cols = []string{"Field", "Type", "Collation", "Null", "Key", "Default", "Extra", "Privileges", "Comment"}
	}
	res := &SQLResult{Columns: cols, IsSet: true}
	for _, c := range tbl.Columns {
		null := "NO"
		if c.Nullable {
			null = "YES"
		}
		var row []*string
		if full {
			coll := "utf8mb4_unicode_ci"
			if !strings.Contains(strings.ToLower(c.Type), "char") && !strings.Contains(strings.ToLower(c.Type), "text") && !strings.Contains(strings.ToLower(c.Type), "enum") {
				row = []*string{sp(c.Name), sp(c.Type), nil, sp(null), sp(c.Key), c.Default, sp(c.Extra), sp("select,insert,update,references"), sp("")}
			} else {
				row = []*string{sp(c.Name), sp(c.Type), sp(coll), sp(null), sp(c.Key), c.Default, sp(c.Extra), sp("select,insert,update,references"), sp("")}
			}
		} else {
			row = []*string{sp(c.Name), sp(c.Type), sp(null), sp(c.Key), c.Default, sp(c.Extra)}
		}
		res.Rows = append(res.Rows, row)
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

func (ec *execCtx) showCreateTable(arg string, start time.Time) (*SQLResult, *MySQLError) {
	schema, table := ec.resolveTable(strings.TrimSpace(arg))
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
	ddl := createTableDDL(tbl)
	res := &SQLResult{
		Columns: []string{"Table", "Create Table"},
		Rows:    [][]*string{{sp(tbl.Name), sp(ddl)}},
		IsSet:   true,
		Elapsed: time.Since(start),
	}
	return res, nil
}

func (ec *execCtx) showCreateDatabase(rest string, start time.Time) (*SQLResult, *MySQLError) {
	tok, _ := firstToken(strings.TrimSpace(rest[strings.IndexAny(rest, " \t"):]))
	name := strings.Trim(tok, "`\"'")
	if name == "" {
		name = ec.curDB
	}
	if !ec.srv.schemaExists(name) || !canUseSchema(ec.acct, name) {
		return nil, myErr(1049, "42000", "Unknown database '%s'", name)
	}
	ddl := fmt.Sprintf("CREATE DATABASE `%s` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */", name)
	return &SQLResult{Columns: []string{"Database", "Create Database"}, Rows: [][]*string{{sp(name), sp(ddl)}}, IsSet: true, Elapsed: time.Since(start)}, nil
}

func (ec *execCtx) showGrants(rest string, start time.Time) (*SQLResult, *MySQLError) {
	target := ec.acct
	hdrUser := ec.user + "@" + ec.host
	rest = strings.TrimSpace(rest[len("grants"):])
	if f := cutPrefixFold(rest, "for "); f != "" {
		spec := strings.TrimSpace(f)
		uname := strings.Trim(firstFieldBefore(spec, '@'), "`\"' ")
		if a := ec.srv.account(uname); a != nil {
			target = a
			hdrUser = a.User + "@" + a.Host
		} else {
			return nil, myErr(1141, "42000", "There is no such grant defined for user '%s' on host '%%'", uname)
		}
	}
	if target == nil {
		return nil, myErr(1141, "42000", "There is no such grant defined for user '%s' on host '%%'", ec.user)
	}
	res := &SQLResult{Columns: []string{"Grants for " + hdrUser}, IsSet: true}
	for _, g := range target.Grants {
		res.Rows = append(res.Rows, []*string{sp(g)})
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

// a short, believable subset of SHOW VARIABLES.
func (ec *execCtx) showVariables(rest string, start time.Time) (*SQLResult, *MySQLError) {
	rest = strings.TrimSpace(rest[len("variables"):])
	rest = strings.TrimSpace(trimPrefixFold(rest, "global "))
	rest = strings.TrimSpace(trimPrefixFold(rest, "session "))
	like := parseLike(rest)
	vars := [][2]string{
		{"auto_increment_increment", "1"},
		{"autocommit", "ON"},
		{"basedir", mysqlBaseDir},
		{"character_set_client", "utf8mb4"},
		{"character_set_connection", "utf8mb4"},
		{"character_set_database", "latin1"},
		{"character_set_server", "latin1"},
		{"collation_server", "latin1_swedish_ci"},
		{"datadir", mysqlDataDir},
		{"hostname", mysqlServerHostShort},
		{"max_allowed_packet", "67108864"},
		{"max_connections", "151"},
		{"port", "3306"},
		{"secure_file_priv", ""},
		{"socket", mysqlSocket},
		{"version", mysqlServerVersion},
		{"version_comment", "MySQL Community Server (GPL)"},
		{"version_compile_machine", "x86_64"},
		{"version_compile_os", "Linux"},
		{"wait_timeout", "28800"},
	}
	res := &SQLResult{Columns: []string{"Variable_name", "Value"}, IsSet: true}
	for _, v := range vars {
		if like != "" && !likeMatch(like, v[0]) {
			continue
		}
		res.Rows = append(res.Rows, []*string{sp(v[0]), sp(v[1])})
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

func (ec *execCtx) showStatus(start time.Time) (*SQLResult, *MySQLError) {
	rows := [][2]string{
		{"Aborted_clients", "3"}, {"Aborted_connects", "1"}, {"Bytes_received", "1843221"},
		{"Bytes_sent", "9273811"}, {"Connections", "48213"}, {"Max_used_connections", "37"},
		{"Open_tables", "128"}, {"Queries", "2841923"}, {"Questions", "118223"},
		{"Threads_connected", "4"}, {"Threads_running", "1"}, {"Uptime", "1398241"},
	}
	res := &SQLResult{Columns: []string{"Variable_name", "Value"}, IsSet: true}
	for _, r := range rows {
		res.Rows = append(res.Rows, []*string{sp(r[0]), sp(r[1])})
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

func (ec *execCtx) showProcesslist(start time.Time) (*SQLResult, *MySQLError) {
	res := &SQLResult{Columns: []string{"Id", "User", "Host", "db", "Command", "Time", "State", "Info"}, IsSet: true}
	db := ec.curDB
	var dbp *string
	if db != "" {
		dbp = sp(db)
	}
	res.Rows = append(res.Rows, []*string{sp("48213"), sp(ec.user), sp(ec.host + ":52214"), dbp, sp("Query"), sp("0"), sp("starting"), sp("show processlist")})
	res.Rows = append(res.Rows, []*string{sp("48198"), sp("connect_app"), sp(mysqlClientIP + ":41882"), sp("veltrona_connect"), sp("Sleep"), sp("42"), sp(""), nil})
	res.Elapsed = time.Since(start)
	return res, nil
}

func (ec *execCtx) showEngines(start time.Time) (*SQLResult, *MySQLError) {
	cols := []string{"Engine", "Support", "Comment", "Transactions", "XA", "Savepoints"}
	res := &SQLResult{Columns: cols, IsSet: true}
	res.Rows = append(res.Rows, []*string{sp("InnoDB"), sp("DEFAULT"), sp("Supports transactions, row-level locking, and foreign keys"), sp("YES"), sp("YES"), sp("YES")})
	res.Rows = append(res.Rows, []*string{sp("MyISAM"), sp("YES"), sp("MyISAM storage engine"), sp("NO"), sp("NO"), sp("NO")})
	res.Rows = append(res.Rows, []*string{sp("MEMORY"), sp("YES"), sp("Hash based, stored in memory, useful for temporary tables"), sp("NO"), sp("NO"), sp("NO")})
	res.Elapsed = time.Since(start)
	return res, nil
}

func (ec *execCtx) showCharset(start time.Time) (*SQLResult, *MySQLError) {
	cols := []string{"Charset", "Description", "Default collation", "Maxlen"}
	res := &SQLResult{Columns: cols, IsSet: true}
	res.Rows = append(res.Rows, []*string{sp("latin1"), sp("cp1252 West European"), sp("latin1_swedish_ci"), sp("1")})
	res.Rows = append(res.Rows, []*string{sp("utf8"), sp("UTF-8 Unicode"), sp("utf8_general_ci"), sp("3")})
	res.Rows = append(res.Rows, []*string{sp("utf8mb4"), sp("UTF-8 Unicode"), sp("utf8mb4_general_ci"), sp("4")})
	res.Elapsed = time.Since(start)
	return res, nil
}

// createTableDDL synthesizes a realistic CREATE TABLE statement.
func createTableDDL(t *Table) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CREATE TABLE `%s` (\n", t.Name)
	var lines []string
	var pk []string
	for _, c := range t.Columns {
		line := "  `" + c.Name + "` " + c.Type
		if !c.Nullable {
			line += " NOT NULL"
		} else {
			line += " DEFAULT NULL"
		}
		if c.Default != nil {
			line += " DEFAULT " + quoteDefault(*c.Default)
		}
		if c.Extra != "" {
			line += " " + c.Extra
		}
		lines = append(lines, line)
		if c.Key == "PRI" {
			pk = append(pk, "`"+c.Name+"`")
		}
	}
	if len(pk) > 0 {
		lines = append(lines, "  PRIMARY KEY ("+strings.Join(pk, ",")+")")
	}
	for _, c := range t.Columns {
		if c.Key == "UNI" {
			lines = append(lines, "  UNIQUE KEY `"+c.Name+"` (`"+c.Name+"`)")
		} else if c.Key == "MUL" {
			lines = append(lines, "  KEY `"+c.Name+"` (`"+c.Name+"`)")
		}
	}
	b.WriteString(strings.Join(lines, ",\n"))
	eng := t.Engine
	if eng == "" {
		eng = "InnoDB"
	}
	fmt.Fprintf(&b, "\n) ENGINE=%s", eng)
	if t.AutoIncrement > 0 {
		fmt.Fprintf(&b, " AUTO_INCREMENT=%d", t.AutoIncrement)
	}
	b.WriteString(" DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci")
	if t.Comment != "" {
		fmt.Fprintf(&b, " COMMENT='%s'", strings.ReplaceAll(t.Comment, "'", "''"))
	}
	return b.String()
}

func quoteDefault(d string) string {
	switch strings.ToUpper(d) {
	case "CURRENT_TIMESTAMP", "NULL":
		return d
	}
	return "'" + strings.ReplaceAll(d, "'", "''") + "'"
}
