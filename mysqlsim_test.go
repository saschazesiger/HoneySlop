package main

import (
	"context"
	"strings"
	"testing"
)

// ---- fixtures: a hand-built world + databases (no GenerateWorld / bcrypt) ----

func mysqlTestWorld() *World {
	w := &World{
		MySQL: map[string]*MySQLAccount{
			"connect_app": {User: "connect_app", Host: "10.20.2.%", Password: "connectpw", DBs: []string{"veltrona_connect"},
				Grants: []string{
					"GRANT USAGE ON *.* TO 'connect_app'@'10.20.2.%'",
					"GRANT ALL PRIVILEGES ON `veltrona_connect`.* TO 'connect_app'@'10.20.2.%'",
				}},
			"wp_blog": {User: "wp_blog", Host: "10.20.2.%", Password: "wppw", DBs: []string{"veltrona_wp"},
				Grants: []string{"GRANT SELECT, INSERT, UPDATE, DELETE ON `veltrona_wp`.* TO 'wp_blog'@'10.20.2.%'"}},
			"backup": {User: "backup", Host: "10.20.%", Password: "backuppw", ReadOnly: true, DBs: []string{"*"},
				Grants: []string{"GRANT SELECT, LOCK TABLES ON *.* TO 'backup'@'10.20.%'"}},
			"root": {User: "root", Host: "%", Password: "rootpw", DBs: []string{"*"},
				Grants: []string{"GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION"}},
		},
	}
	w.dbs = testDatabases()
	return w
}

func col(name, typ, key string) Column { return Column{Name: name, Type: typ, Key: key} }

func testDatabases() []Database {
	return []Database{
		{Name: "veltrona_connect", Tables: []Table{
			{Name: "users", Engine: "InnoDB", AutoIncrement: 15, Columns: []Column{
				col("id", "int(10) unsigned", "PRI"),
				col("name", "varchar(255)", ""),
				col("email", "varchar(255)", "UNI"),
				col("role", "varchar(32)", ""),
			}, Rows: [][]any{
				{int64(1), "Daniel Kessler", "daniel.kessler@veltrona-group.com", "admin"},
				{int64(2), "Marco Bianchi", "marco.bianchi@veltrona-group.com", "staff"},
				{int64(3), "Lukas Meier", "l.meier@alpenfrost.ch", "customer"},
			}},
			{Name: "orders", Engine: "InnoDB", Columns: []Column{
				col("id", "bigint(20) unsigned", "PRI"),
				col("customer_id", "int(10) unsigned", "MUL"),
				col("total", "decimal(10,2)", ""),
			}, Rows: [][]any{
				{int64(1001), int64(100), "249.90"},
			}},
		}},
		{Name: "veltrona_wp", Tables: []Table{
			{Name: "wp_users", Engine: "InnoDB", Columns: []Column{
				col("ID", "bigint(20) unsigned", "PRI"),
				col("user_login", "varchar(60)", "MUL"),
				col("user_pass", "varchar(255)", ""),
			}, Rows: [][]any{
				{int64(1), "veltrona-admin", "$P$Bxxxxxxxxxxxxxxxxxxxxxxxxxx0"},
			}},
		}},
		{Name: "mysql", Tables: []Table{
			{Name: "user", Engine: "MyISAM", Columns: []Column{
				col("Host", "char(60)", "PRI"),
				col("User", "char(32)", "PRI"),
				col("authentication_string", "text", ""),
			}, Rows: [][]any{
				{"%", "root", "*ABC"},
				{"10.20.2.%", "connect_app", "*DEF"},
			}},
		}},
	}
}

func newTestServer(t *testing.T) *MySQLServer {
	t.Helper()
	return NewMySQLServer(mysqlTestWorld())
}

// ---- helpers ----

func mustQuery(t *testing.T, s *MySQLServer, user, db, q string) *SQLResult {
	t.Helper()
	r, me := s.Query(context.Background(), user, db, q)
	if me != nil {
		t.Fatalf("Query(%q) unexpected error: %v", q, me)
	}
	return r
}

func cellAt(r *SQLResult, row, col int) string {
	if row >= len(r.Rows) || col >= len(r.Rows[row]) {
		return "<oob>"
	}
	if r.Rows[row][col] == nil {
		return "NULL"
	}
	return *r.Rows[row][col]
}

// ---- tests ----

func TestShowDatabasesVisibility(t *testing.T) {
	s := newTestServer(t)
	cases := []struct {
		user string
		want []string
		deny []string
	}{
		{"connect_app", []string{"information_schema", "veltrona_connect"}, []string{"veltrona_wp", "mysql"}},
		{"wp_blog", []string{"information_schema", "veltrona_wp"}, []string{"veltrona_connect", "mysql"}},
		{"root", []string{"information_schema", "mysql", "performance_schema", "sys", "veltrona_connect", "veltrona_wp"}, nil},
	}
	for _, c := range cases {
		r := mustQuery(t, s, c.user, "", "SHOW DATABASES")
		got := map[string]bool{}
		for _, row := range r.Rows {
			got[*row[0]] = true
		}
		for _, w := range c.want {
			if !got[w] {
				t.Errorf("%s: SHOW DATABASES missing %q (got %v)", c.user, w, got)
			}
		}
		for _, d := range c.deny {
			if got[d] {
				t.Errorf("%s: SHOW DATABASES unexpectedly shows %q", c.user, d)
			}
		}
	}
}

func TestUseAndSelect(t *testing.T) {
	s := newTestServer(t)
	r := mustQuery(t, s, "connect_app", "veltrona_connect", "SELECT id, name FROM users ORDER BY id")
	if len(r.Rows) != 3 {
		t.Fatalf("want 3 rows, got %d", len(r.Rows))
	}
	if cellAt(r, 0, 1) != "Daniel Kessler" {
		t.Errorf("row0 name = %q", cellAt(r, 0, 1))
	}
}

func TestNoDatabaseSelected(t *testing.T) {
	s := newTestServer(t)
	_, me := s.Query(context.Background(), "connect_app", "", "SELECT * FROM users")
	if me == nil || me.Code != 1046 {
		t.Fatalf("want 1046, got %v", me)
	}
}

func TestPrivilegeDeniedCrossSchema(t *testing.T) {
	s := newTestServer(t)
	// connect_app cannot read veltrona_wp
	_, me := s.Query(context.Background(), "connect_app", "veltrona_connect", "SELECT * FROM veltrona_wp.wp_users")
	if me == nil || me.Code != 1142 {
		t.Fatalf("want 1142, got %v", me)
	}
	// but root can
	r := mustQuery(t, s, "root", "", "SELECT user_login FROM veltrona_wp.wp_users")
	if len(r.Rows) != 1 {
		t.Fatalf("root cross-schema read failed: %d rows", len(r.Rows))
	}
}

func TestReadOnlyBackupWriteDenied(t *testing.T) {
	s := newTestServer(t)
	_, me := s.Query(context.Background(), "backup", "veltrona_connect", "DELETE FROM users WHERE id=1")
	if me == nil || me.Code != 1142 {
		t.Fatalf("want 1142 for read-only write, got %v", me)
	}
}

func TestUnknownDatabase(t *testing.T) {
	s := newTestServer(t)
	_, me := s.Query(context.Background(), "root", "", "USE nope")
	if me == nil || me.Code != 1049 {
		t.Fatalf("want 1049, got %v", me)
	}
}

func TestUnknownTableAndColumn(t *testing.T) {
	s := newTestServer(t)
	_, me := s.Query(context.Background(), "connect_app", "veltrona_connect", "SELECT * FROM ghosts")
	if me == nil || me.Code != 1146 {
		t.Fatalf("want 1146, got %v", me)
	}
	_, me = s.Query(context.Background(), "connect_app", "veltrona_connect", "SELECT nope FROM users")
	if me == nil || me.Code != 1054 {
		t.Fatalf("want 1054, got %v", me)
	}
}

func TestInformationSchemaTables(t *testing.T) {
	s := newTestServer(t)
	r := mustQuery(t, s, "connect_app", "veltrona_connect",
		"SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA='veltrona_connect' ORDER BY TABLE_NAME")
	var names []string
	for _, row := range r.Rows {
		names = append(names, *row[0])
	}
	if strings.Join(names, ",") != "orders,users" {
		t.Fatalf("information_schema.tables = %v", names)
	}
	// connect_app must not see wp tables in information_schema
	r = mustQuery(t, s, "connect_app", "veltrona_connect",
		"SELECT COUNT(*) FROM information_schema.columns WHERE TABLE_SCHEMA='veltrona_wp'")
	if cellAt(r, 0, 0) != "0" {
		t.Errorf("connect_app sees veltrona_wp columns: %s", cellAt(r, 0, 0))
	}
}

func TestInformationSchemaColumns(t *testing.T) {
	s := newTestServer(t)
	r := mustQuery(t, s, "connect_app", "veltrona_connect",
		"SELECT COLUMN_NAME, DATA_TYPE, COLUMN_KEY FROM information_schema.columns WHERE TABLE_SCHEMA='veltrona_connect' AND TABLE_NAME='users' ORDER BY ORDINAL_POSITION")
	if len(r.Rows) != 4 {
		t.Fatalf("want 4 columns, got %d", len(r.Rows))
	}
	if cellAt(r, 0, 0) != "id" || cellAt(r, 0, 1) != "int" || cellAt(r, 0, 2) != "PRI" {
		t.Errorf("first column row = %v", r.Rows[0])
	}
}

func TestSpecialSelects(t *testing.T) {
	s := newTestServer(t)
	r := mustQuery(t, s, "connect_app", "veltrona_connect", "SELECT version()")
	if cellAt(r, 0, 0) != mysqlServerVersion {
		t.Errorf("version() = %q", cellAt(r, 0, 0))
	}
	r = mustQuery(t, s, "connect_app", "veltrona_connect", "SELECT database()")
	if cellAt(r, 0, 0) != "veltrona_connect" {
		t.Errorf("database() = %q", cellAt(r, 0, 0))
	}
	r = mustQuery(t, s, "connect_app", "veltrona_connect", "SELECT user()")
	if cellAt(r, 0, 0) != "connect_app@"+mysqlClientIP {
		t.Errorf("user() = %q", cellAt(r, 0, 0))
	}
	r = mustQuery(t, s, "connect_app", "veltrona_connect", "SELECT @@version_comment")
	if !strings.Contains(cellAt(r, 0, 0), "MySQL") {
		t.Errorf("@@version_comment = %q", cellAt(r, 0, 0))
	}
}

func TestShowGrants(t *testing.T) {
	s := newTestServer(t)
	r := mustQuery(t, s, "root", "", "SHOW GRANTS")
	if len(r.Rows) == 0 || !strings.Contains(*r.Rows[0][0], "ALL PRIVILEGES") {
		t.Fatalf("SHOW GRANTS for root = %v", r.Rows)
	}
	if !strings.HasPrefix(r.Columns[0], "Grants for root@") {
		t.Errorf("grants header = %q", r.Columns[0])
	}
}

func TestShowCreateTable(t *testing.T) {
	s := newTestServer(t)
	r := mustQuery(t, s, "connect_app", "veltrona_connect", "SHOW CREATE TABLE users")
	ddl := cellAt(r, 0, 1)
	if !strings.Contains(ddl, "CREATE TABLE `users`") || !strings.Contains(ddl, "PRIMARY KEY (`id`)") ||
		!strings.Contains(ddl, "ENGINE=InnoDB") {
		t.Fatalf("unexpected DDL:\n%s", ddl)
	}
}

func TestDescribe(t *testing.T) {
	s := newTestServer(t)
	r := mustQuery(t, s, "connect_app", "veltrona_connect", "DESCRIBE users")
	if len(r.Rows) != 4 || r.Columns[0] != "Field" {
		t.Fatalf("DESCRIBE users = %v cols=%v", r.Rows, r.Columns)
	}
}

func TestShowColumnsAndTables(t *testing.T) {
	s := newTestServer(t)
	r := mustQuery(t, s, "connect_app", "veltrona_connect", "SHOW TABLES")
	if r.Columns[0] != "Tables_in_veltrona_connect" || len(r.Rows) != 2 {
		t.Fatalf("SHOW TABLES = cols %v rows %d", r.Columns, len(r.Rows))
	}
	r = mustQuery(t, s, "connect_app", "veltrona_connect", "SHOW COLUMNS FROM users")
	if len(r.Rows) != 4 {
		t.Fatalf("SHOW COLUMNS rows = %d", len(r.Rows))
	}
}

func TestWriteInSession(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	// interactive/batch instance persists writes
	inst, _ := s.getSessionInstance("sid1", s.account("connect_app"), mysqlClientIP)
	ec := &execCtx{srv: s, inst: inst, acct: s.account("connect_app"), user: "connect_app", host: mysqlClientIP, curDB: "veltrona_connect"}
	if _, me := ec.runStatement(ctx, "INSERT INTO users (id,name,email,role) VALUES (99,'Temp','t@x.ch','staff')"); me != nil {
		t.Fatalf("insert failed: %v", me)
	}
	r, me := ec.runStatement(ctx, "SELECT COUNT(*) FROM users")
	if me != nil {
		t.Fatalf("count failed: %v", me)
	}
	if cellAt(r, 0, 0) != "4" {
		t.Errorf("after insert count = %s", cellAt(r, 0, 0))
	}
}

func TestWebQueryRollsBackWrites(t *testing.T) {
	s := newTestServer(t)
	// web write is reported OK but does not persist
	r, me := s.Query(context.Background(), "connect_app", "veltrona_connect", "DELETE FROM users WHERE id=1")
	if me != nil {
		t.Fatalf("web delete err: %v", me)
	}
	if r.Affected != 1 {
		t.Errorf("affected = %d", r.Affected)
	}
	r = mustQuery(t, s, "connect_app", "veltrona_connect", "SELECT COUNT(*) FROM users")
	if cellAt(r, 0, 0) != "3" {
		t.Errorf("rows changed after rolled-back web write: %s", cellAt(r, 0, 0))
	}
}

func TestSchemaMap(t *testing.T) {
	s := newTestServer(t)
	m := s.Schema("connect_app")
	if _, ok := m["veltrona_connect"]; !ok {
		t.Fatalf("Schema missing veltrona_connect: %v", m)
	}
	if _, ok := m["veltrona_wp"]; ok {
		t.Errorf("connect_app should not see veltrona_wp in Schema")
	}
	tables := m["veltrona_connect"]
	if len(tables) != 2 {
		t.Errorf("veltrona_connect tables = %v", tables)
	}
}

// ---- client option parsing ----

func TestParseArgs(t *testing.T) {
	o := parseMySQLArgs([]string{"-uroot", "-psecret", "-h", "db-prod-01", "-D", "veltrona_connect", "-e", "select 1"})
	if o.user != "root" || !o.hasUser {
		t.Errorf("user = %q", o.user)
	}
	if o.password != "secret" || !o.inlinePass {
		t.Errorf("password = %q inline=%v", o.password, o.inlinePass)
	}
	if o.host != "db-prod-01" {
		t.Errorf("host = %q", o.host)
	}
	if o.database != "veltrona_connect" {
		t.Errorf("db = %q", o.database)
	}
	if o.execute != "select 1" || !o.hasExecute {
		t.Errorf("execute = %q", o.execute)
	}

	o = parseMySQLArgs([]string{"--user=backup", "--password=pw", "--batch", "--skip-column-names", "mydb"})
	if o.user != "backup" || o.password != "pw" || !o.batch || !o.skipCols {
		t.Errorf("long opts: %+v", o)
	}
	if len(o.positional) != 1 || o.positional[0] != "mydb" {
		t.Errorf("positional = %v", o.positional)
	}

	o = parseMySQLArgs([]string{"-u", "root", "-p"})
	if !o.wantPass || o.inlinePass {
		t.Errorf("bare -p should want prompt: %+v", o)
	}
}

func TestInvokeLocalSocketNoHost(t *testing.T) {
	s := newTestServer(t)
	run := s.Invoke(context.Background(), "s", "mysql", []string{"-uconnect_app", "-pconnectpw"}, "www-data", "")
	if !strings.Contains(run.Output, "ERROR 2002") {
		t.Fatalf("want 2002 socket error, got: %q", run.Output)
	}
	if !strings.Contains(run.Output, "Using a password on the command line") {
		t.Errorf("missing CLI password warning: %q", run.Output)
	}
}

func TestInvokeUnknownHost(t *testing.T) {
	s := newTestServer(t)
	run := s.Invoke(context.Background(), "s", "mysql", []string{"-uroot", "-prootpw", "-h", "nosuch.host"}, "www-data", "")
	if !strings.Contains(run.Output, "ERROR 2005") {
		t.Fatalf("want 2005, got: %q", run.Output)
	}
	run = s.Invoke(context.Background(), "s", "mysql", []string{"-uroot", "-prootpw", "-h", "10.99.99.99"}, "www-data", "")
	if !strings.Contains(run.Output, "ERROR 2003") {
		t.Fatalf("want 2003, got: %q", run.Output)
	}
}

func TestInvokeAccessDenied(t *testing.T) {
	s := newTestServer(t)
	run := s.Invoke(context.Background(), "s", "mysql", []string{"-uconnect_app", "-pwrong", "-hdb-prod-01"}, "www-data", "")
	if !strings.Contains(run.Output, "ERROR 1045 (28000)") || !strings.Contains(run.Output, "using password: YES") {
		t.Fatalf("want 1045 YES, got: %q", run.Output)
	}
	if run.Authed != "" {
		t.Errorf("Authed should be empty on failure, got %q", run.Authed)
	}
}

func TestInvokeBatchExecute(t *testing.T) {
	s := newTestServer(t)
	run := s.Invoke(context.Background(), "s", "mysql",
		[]string{"-uconnect_app", "-pconnectpw", "-hdb-prod-01", "-e", "SELECT id,name FROM users ORDER BY id", "veltrona_connect"}, "www-data", "")
	if run.Authed != "connect_app" {
		t.Fatalf("Authed = %q", run.Authed)
	}
	// -e on a (pseudo) tty prints the box table
	if !strings.Contains(run.Output, "Daniel Kessler") || !strings.Contains(run.Output, "+----") {
		t.Fatalf("batch output:\n%s", run.Output)
	}
}

func TestInvokeStdinBatchTabbed(t *testing.T) {
	s := newTestServer(t)
	run := s.Invoke(context.Background(), "s2", "mysql",
		[]string{"-uconnect_app", "-pconnectpw", "-hdb-prod-01", "veltrona_connect"}, "www-data", "SELECT id,name FROM users ORDER BY id\n")
	// piped stdin => tab separated, no box
	if strings.Contains(run.Output, "+----") {
		t.Fatalf("stdin batch should be tab separated:\n%s", run.Output)
	}
	if !strings.Contains(run.Output, "id\tname") {
		t.Fatalf("missing tab header:\n%s", run.Output)
	}
}

func TestPasswordPromptContinue(t *testing.T) {
	s := newTestServer(t)
	run := s.Invoke(context.Background(), "s3", "mysql", []string{"-uroot", "-p", "-hdb-prod-01"}, "www-data", "")
	if !run.NeedPassword || run.Pending == nil {
		t.Fatalf("expected password prompt: %+v", run)
	}
	run = s.Continue(context.Background(), "s3", *run.Pending, "www-data", "rootpw")
	if run.Interactive == nil || run.Authed != "root" {
		t.Fatalf("continue should authenticate root interactively: %+v, out=%q", run, run.Output)
	}
	if !strings.Contains(run.Output, "Welcome to the MySQL monitor") {
		t.Errorf("missing banner: %q", run.Output)
	}
}

func TestRootMyCnf(t *testing.T) {
	s := newTestServer(t)
	// localUser root, no -u/-p: uses /root/.my.cnf (user=root host=db-prod-01)
	run := s.Invoke(context.Background(), "s4", "mysql", nil, "root", "")
	if run.Interactive == nil || run.Authed != "root" {
		t.Fatalf("root .my.cnf login failed: out=%q run=%+v", run.Output, run)
	}
}

func TestInteractiveFlow(t *testing.T) {
	s := newTestServer(t)
	run := s.Invoke(context.Background(), "s5", "mysql", []string{"-uconnect_app", "-pconnectpw", "-hdb-prod-01"}, "www-data", "")
	if run.Interactive == nil {
		t.Fatalf("expected interactive, got %q", run.Output)
	}
	c := *run.Interactive
	// multi-line buffering
	out, next, prompt := s.Line(context.Background(), "s5", c, "SELECT id, name")
	if next == nil || prompt != promptCont || out != "" {
		t.Fatalf("continuation: out=%q prompt=%q", out, prompt)
	}
	out, next, prompt = s.Line(context.Background(), "s5", *next, "FROM veltrona_connect.users ORDER BY id;")
	if !strings.Contains(out, "Daniel Kessler") || prompt != promptMain {
		t.Fatalf("exec: out=%q prompt=%q", out, prompt)
	}
	// USE as client command
	out, next, _ = s.Line(context.Background(), "s5", *next, "use veltrona_connect")
	if !strings.Contains(out, "Database changed") || next.DB != "veltrona_connect" {
		t.Fatalf("use: out=%q db=%q", out, next.DB)
	}
	// vertical terminator
	out, next, _ = s.Line(context.Background(), "s5", *next, "SELECT id,name FROM users WHERE id=1\\G")
	if !strings.Contains(out, "*************************** 1. row") || !strings.Contains(out, "name: Daniel Kessler") {
		t.Fatalf("vertical: %q", out)
	}
	// quit
	out, next, _ = s.Line(context.Background(), "s5", *next, "exit")
	if next != nil || !strings.Contains(out, "Bye") {
		t.Fatalf("quit: out=%q next=%v", out, next)
	}
}

func TestInteractiveStatusAndHelp(t *testing.T) {
	s := newTestServer(t)
	run := s.Invoke(context.Background(), "s6", "mysql", []string{"-uroot", "-prootpw", "-hdb-prod-01"}, "www-data", "")
	c := *run.Interactive
	out, _, _ := s.Line(context.Background(), "s6", c, "status")
	if !strings.Contains(out, "Server version:") || !strings.Contains(out, "Current user:\t\troot@") {
		t.Fatalf("status: %q", out)
	}
	out, _, _ = s.Line(context.Background(), "s6", c, "help")
	if !strings.Contains(out, "List of all MySQL commands") {
		t.Fatalf("help: %q", out)
	}
}

func TestVersionFlag(t *testing.T) {
	s := newTestServer(t)
	run := s.Invoke(context.Background(), "s", "mysql", []string{"--version"}, "www-data", "")
	if !strings.Contains(run.Output, "Ver "+mysqlClientVersion) {
		t.Fatalf("version: %q", run.Output)
	}
}

// ---- mysqldump ----

func TestMysqldump(t *testing.T) {
	s := newTestServer(t)
	run := s.Invoke(context.Background(), "d1", "mysqldump",
		[]string{"-uconnect_app", "-pconnectpw", "-hdb-prod-01", "veltrona_connect"}, "www-data", "")
	if run.Authed != "connect_app" {
		t.Fatalf("dump authed = %q", run.Authed)
	}
	out := run.Output
	for _, want := range []string{
		"-- MySQL dump 10.13", "CREATE TABLE `users`", "INSERT INTO `users` VALUES",
		"Daniel Kessler", "LOCK TABLES `users` WRITE", "Dump completed on",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dump missing %q", want)
		}
	}
}

func TestMysqldumpNoData(t *testing.T) {
	s := newTestServer(t)
	run := s.Invoke(context.Background(), "d2", "mysqldump",
		[]string{"-uconnect_app", "-pconnectpw", "-hdb-prod-01", "--no-data", "veltrona_connect"}, "www-data", "")
	if strings.Contains(run.Output, "INSERT INTO `users` VALUES") {
		t.Fatalf("--no-data should not emit INSERTs:\n%s", run.Output)
	}
	if !strings.Contains(run.Output, "CREATE TABLE `users`") {
		t.Errorf("--no-data should still emit DDL")
	}
}

func TestMysqldumpPrivilegeError(t *testing.T) {
	s := newTestServer(t)
	run := s.Invoke(context.Background(), "d3", "mysqldump",
		[]string{"-uconnect_app", "-pconnectpw", "-hdb-prod-01", "veltrona_wp"}, "www-data", "")
	if !strings.Contains(run.Output, "mysqldump: Got error: 1044") {
		t.Fatalf("want 1044 dump error, got:\n%s", run.Output)
	}
}

// ---- formatting ----

func TestFormatTable(t *testing.T) {
	r := &SQLResult{
		Columns: []string{"id", "name"},
		Rows:    [][]*string{{sp("1"), sp("Daniel")}, {sp("2"), nil}},
		IsSet:   true,
	}
	out := FormatMySQLTable(r)
	if !strings.Contains(out, "+----+--------+") {
		t.Errorf("missing box rule:\n%s", out)
	}
	if !strings.Contains(out, "| id | name   |") {
		t.Errorf("header:\n%s", out)
	}
	if !strings.Contains(out, "NULL") {
		t.Errorf("NULL cell:\n%s", out)
	}
	if !strings.Contains(out, "2 rows in set") {
		t.Errorf("footer:\n%s", out)
	}
}

func TestFormatEmptyAndOK(t *testing.T) {
	empty := FormatMySQLTable(&SQLResult{Columns: []string{"id"}, IsSet: true})
	if !strings.Contains(empty, "Empty set") {
		t.Errorf("empty set: %q", empty)
	}
	ok := FormatMySQLTable(&SQLResult{Affected: 1})
	if !strings.Contains(ok, "Query OK, 1 row affected") {
		t.Errorf("ok packet: %q", ok)
	}
	changed := FormatMySQLTable(&SQLResult{Info: "Database changed"})
	if strings.TrimSpace(changed) != "Database changed" {
		t.Errorf("db changed: %q", changed)
	}
}

func TestSyntaxErrorMapsTo1064(t *testing.T) {
	s := newTestServer(t)
	_, me := s.Query(context.Background(), "connect_app", "veltrona_connect", "SELZECT bogus FRM")
	if me == nil || me.Code != 1064 {
		t.Fatalf("want 1064, got %v", me)
	}
	if !strings.Contains(me.Msg, "You have an error in your SQL syntax") {
		t.Errorf("1064 text: %q", me.Msg)
	}
}
