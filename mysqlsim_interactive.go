package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	promptMain = "mysql> "
	promptCont = "    -> "
)

// Line processes one input line of the interactive monitor. It returns the
// output produced, the next client state (nil = the client quit), and the next
// prompt to display.
func (s *MySQLServer) Line(ctx context.Context, sid string, c MySQLClient, line string) (string, *MySQLClient, string) {
	acct := s.account(c.User)
	host := c.Host
	if host == "" {
		host = mysqlClientIP
	}

	// Client builtins are recognized only when no statement is buffered.
	if c.Buf == "" {
		if out, next, prompt, handled := s.clientCommand(sid, c, strings.TrimSpace(line)); handled {
			return out, next, prompt
		}
	}

	buf := c.Buf + line + "\n"
	items, leftover := extractStatements(buf)

	inst, err := s.getSessionInstance(sid, acct, host)
	if err != nil {
		return "ERROR 1105 (HY000): Unknown error\n", &c, promptMain
	}
	ec := &execCtx{srv: s, inst: inst, acct: acct, user: c.User, host: host, curDB: c.DB}

	var out strings.Builder
	for _, it := range items {
		if strings.TrimSpace(it.sql) == "" {
			continue
		}
		res, me := ec.runStatement(ctx, it.sql)
		if me != nil {
			out.WriteString(me.Error() + "\n")
			continue
		}
		if res == nil {
			continue
		}
		switch {
		case res.IsSet && it.vertical:
			out.WriteString(formatVertical(res))
			out.WriteString(fmt.Sprintf("%d %s in set (%.2f sec)\n", len(res.Rows), rowNoun(len(res.Rows)), res.Elapsed.Seconds()))
		case res.IsSet:
			out.WriteString(FormatMySQLTable(res))
		default:
			out.WriteString(FormatMySQLTable(res))
		}
		out.WriteByte('\n')
	}

	next := c
	next.DB = ec.curDB
	prompt := promptMain
	if strings.TrimSpace(leftover) != "" {
		next.Buf = leftover
		prompt = promptCont
	} else {
		next.Buf = "" // only whitespace left: back to a fresh prompt
	}
	return out.String(), &next, prompt
}

func rowNoun(n int) string {
	if n == 1 {
		return "row"
	}
	return "rows"
}

// clientCommand handles mysql client builtins (exit, use, status, help, ...).
func (s *MySQLServer) clientCommand(sid string, c MySQLClient, line string) (string, *MySQLClient, string, bool) {
	if line == "" {
		next := c
		return "", &next, promptMain, true
	}
	low := strings.ToLower(strings.TrimRight(line, ";"))
	low = strings.TrimSpace(low)

	switch {
	case low == "exit" || low == "quit" || low == `\q`:
		return "Bye\n", nil, "", true
	case low == `\c`:
		next := c
		next.Buf = ""
		return "", &next, promptMain, true
	case low == "help" || low == `\h` || low == "?" || low == `\?` || low == `\h;`:
		next := c
		return monitorHelp(), &next, promptMain, true
	case low == "status" || low == `\s`:
		next := c
		return s.statusText(c), &next, promptMain, true
	case strings.HasPrefix(low, "use ") || strings.HasPrefix(low, `\u `):
		name := strings.TrimSpace(line[strings.IndexAny(line, " \t"):])
		name = strings.Trim(strings.TrimRight(name, ";"), "`\"' ")
		next := c
		out, me := s.changeDB(&next, name)
		if me != nil {
			return me.Error() + "\n", &next, promptMain, true
		}
		return out, &next, promptMain, true
	case strings.HasPrefix(low, "source ") || strings.HasPrefix(low, `\. `):
		fname := strings.TrimSpace(line[strings.IndexAny(line, " \t"):])
		next := c
		return fmt.Sprintf("Failed to open file '%s', error: 2\n", fname), &next, promptMain, true
	case strings.HasPrefix(low, "system ") || strings.HasPrefix(low, `\!`):
		next := c
		return "ERROR: The system command is disabled on this server.\n", &next, promptMain, true
	case strings.HasPrefix(low, "delimiter") || strings.HasPrefix(low, `\d`):
		next := c
		return "", &next, promptMain, true // accept and ignore delimiter changes
	}
	return "", nil, "", false
}

func (s *MySQLServer) changeDB(c *MySQLClient, name string) (string, *MySQLError) {
	if name == "" {
		return "", myErrLit(1064, "42000", syntaxNear(""))
	}
	if !s.schemaExists(name) {
		return "", myErr(1049, "42000", "Unknown database '%s'", name)
	}
	acct := s.account(c.User)
	if !canUseSchema(acct, name) {
		host := c.Host
		if host == "" {
			host = mysqlClientIP
		}
		return "", myErr(1044, "42000", "Access denied for user '%s'@'%s' to database '%s'", c.User, host, name)
	}
	c.DB = canonicalSchema(s, name)
	return "Database changed\n", nil
}

// ---- statement scanner for the interactive monitor ----

type stmtItem struct {
	sql      string
	vertical bool
}

// extractStatements pulls complete statements (terminated by ; \g or \G) from
// buf, returning them plus any incomplete remainder.
func extractStatements(buf string) ([]stmtItem, string) {
	var items []stmtItem
	var cur strings.Builder
	var quote byte
	flush := func(vertical bool) {
		items = append(items, stmtItem{sql: cur.String(), vertical: vertical})
		cur.Reset()
	}
	i := 0
	for i < len(buf) {
		c := buf[i]
		if quote != 0 {
			cur.WriteByte(c)
			if c == quote {
				if i+1 < len(buf) && buf[i+1] == quote {
					cur.WriteByte(buf[i+1])
					i += 2
					continue
				}
				quote = 0
			}
			i++
			continue
		}
		switch {
		case c == '\'' || c == '"' || c == '`':
			quote = c
			cur.WriteByte(c)
			i++
		case c == '-' && i+2 < len(buf) && buf[i+1] == '-' && (buf[i+2] == ' ' || buf[i+2] == '\t' || buf[i+2] == '\n'):
			for i < len(buf) && buf[i] != '\n' {
				i++
			}
		case c == '#':
			for i < len(buf) && buf[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(buf) && buf[i+1] == '*':
			versioned := i+2 < len(buf) && buf[i+2] == '!'
			j := i + 2
			for j+1 < len(buf) && !(buf[j] == '*' && buf[j+1] == '/') {
				j++
			}
			end := j + 2
			if end > len(buf) {
				end = len(buf)
			}
			if versioned {
				cur.WriteString(buf[i:end])
			}
			i = end
		case c == ';':
			flush(false)
			i++
		case c == '\\' && i+1 < len(buf) && (buf[i+1] == 'g' || buf[i+1] == 'G'):
			flush(buf[i+1] == 'G')
			i += 2
		default:
			cur.WriteByte(c)
			i++
		}
	}
	return items, cur.String()
}

// ---- banners / help / status ----

func clientVersionLine() string {
	return "mysql  Ver " + mysqlClientVersion + " for Linux on x86_64 ((Ubuntu))"
}

func interactiveBanner() string {
	return "Welcome to the MySQL monitor.  Commands end with ; or \\g.\n" +
		"Your MySQL connection id is 48213\n" +
		"Server version: " + mysqlServerVersion + " (Ubuntu)\n\n" +
		"Copyright (c) 2000, 2023, Oracle and/or its affiliates.\n\n" +
		"Oracle is a registered trademark of Oracle Corporation and/or its\n" +
		"affiliates. Other names may be trademarks of their respective\n" +
		"owners.\n\n" +
		"Type 'help;' or '\\h' for help. Type '\\c' to clear the current input statement.\n\n"
}

func monitorHelp() string {
	return "\nList of all MySQL commands:\n" +
		"Note that all text commands must be first on line and end with ';'\n" +
		"?         (\\?) Synonym for `help'.\n" +
		"clear     (\\c) Clear the current input statement.\n" +
		"connect   (\\r) Reconnect to the server. Optional arguments are db and host.\n" +
		"delimiter (\\d) Set statement delimiter.\n" +
		"ego       (\\G) Send command to mysql server, display result vertically.\n" +
		"exit      (\\q) Exit mysql. Same as quit.\n" +
		"go        (\\g) Send command to mysql server.\n" +
		"help      (\\h) Display this help.\n" +
		"quit      (\\q) Quit mysql.\n" +
		"source    (\\.) Execute an SQL script file. Takes a file name as an argument.\n" +
		"status    (\\s) Get status information from the server.\n" +
		"use       (\\u) Use another database. Takes database name as argument.\n\n"
}

func (s *MySQLServer) statusText(c MySQLClient) string {
	host := c.Host
	if host == "" {
		host = mysqlClientIP
	}
	db := c.DB
	if db == "" {
		db = ""
	}
	var b strings.Builder
	b.WriteString("--------------\n")
	b.WriteString(clientVersionLine() + "\n\n")
	fmt.Fprintf(&b, "Connection id:\t\t48213\n")
	fmt.Fprintf(&b, "Current database:\t%s\n", db)
	fmt.Fprintf(&b, "Current user:\t\t%s@%s\n", c.User, host)
	b.WriteString("SSL:\t\t\tNot in use\n")
	b.WriteString("Current pager:\t\tstdout\n")
	b.WriteString("Using outfile:\t\t''\n")
	b.WriteString("Using delimiter:\t;\n")
	fmt.Fprintf(&b, "Server version:\t\t%s (Ubuntu)\n", mysqlServerVersion)
	b.WriteString("Protocol version:\t10\n")
	fmt.Fprintf(&b, "Connection:\t\t%s via TCP/IP\n", mysqlServerHostFQDN)
	b.WriteString("Server characterset:\tlatin1\n")
	b.WriteString("Db     characterset:\tlatin1\n")
	b.WriteString("Client characterset:\tutf8mb4\n")
	b.WriteString("Conn.  characterset:\tutf8mb4\n")
	fmt.Fprintf(&b, "TCP port:\t\t%d\n", mysqlPort)
	b.WriteString("Uptime:\t\t\t16 days 4 hours 22 min 1 sec\n\n")
	b.WriteString("Threads: 4  Questions: 118223  Slow queries: 0  Opens: 342  Flush tables: 1  Open tables: 128  Queries per second avg: 0.084\n")
	b.WriteString("--------------\n")
	return b.String()
}

func clientHelp(prog string) string {
	if prog == "mysqldump" {
		return "Usage: mysqldump [OPTIONS] database [tables]\n" +
			"OR     mysqldump [OPTIONS] --databases [OPTIONS] DB1 [DB2 DB3...]\n" +
			"OR     mysqldump [OPTIONS] --all-databases [OPTIONS]\n" +
			"Dumping structure and contents of MySQL databases and tables.\n" +
			"  -u, --user=name     User for login if not current user.\n" +
			"  -p, --password[=name] Password to use when connecting to server.\n" +
			"  -h, --host=name     Connect to host.\n" +
			"  -A, --all-databases Dump all the databases.\n" +
			"  -d, --no-data       No row information.\n"
	}
	return "Usage: mysql [OPTIONS] [database]\n" +
		"  -?, --help          Display this help and exit.\n" +
		"  -u, --user=name     User for login if not current user.\n" +
		"  -p, --password[=name] Password to use when connecting to server.\n" +
		"  -h, --host=name     Connect to host.\n" +
		"  -P, --port=#        Port number to use for connection.\n" +
		"  -D, --database=name Database to use.\n" +
		"  -e, --execute=name  Execute command and quit.\n" +
		"  -B, --batch         Print results using tab as the column separator.\n" +
		"  -N, --skip-column-names Don't write column names in results.\n" +
		"  -E, --vertical      Print the output of a query (rows) vertically.\n" +
		"  -t, --table         Output in table format.\n" +
		"  -V, --version       Output version information and exit.\n"
}

// ---- mysqldump ----

func (s *MySQLServer) runDump(ctx context.Context, sid string, o *mysqlOpts, acct *MySQLAccount, user, db string) string {
	var b strings.Builder
	databasesMode := o.databasesSet || o.batch // mysqldump -B == --databases

	// Determine target schemas and (optionally) table filter.
	var schemas []string
	tableFilter := map[string]bool{}
	switch {
	case o.allDatabases:
		for _, d := range s.w.dbs {
			schemas = append(schemas, d.Name)
		}
	case databasesMode:
		schemas = append(schemas, o.positional...)
		if db != "" {
			schemas = append([]string{db}, schemas...)
		}
	default:
		if db == "" && len(o.positional) == 0 {
			return "mysqldump: Got error: 1049: Unknown database '' when selecting the database\n"
		}
		target := db
		rest := o.positional
		if target == "" && len(o.positional) > 0 {
			target = o.positional[0]
			rest = o.positional[1:]
		}
		schemas = []string{target}
		for _, t := range rest {
			tableFilter[strings.ToLower(t)] = true
		}
	}

	b.WriteString(dumpHeader(schemasLabel(schemas)))

	for _, sc := range schemas {
		if !s.schemaExists(sc) {
			return fmt.Sprintf("mysqldump: Got error: 1049: Unknown database '%s' when selecting the database\n", sc)
		}
		if !canUseSchema(acct, sc) {
			return fmt.Sprintf("mysqldump: Got error: 1044: Access denied for user '%s'@'%s' to database '%s' when using LOCK TABLES\n",
				user, mysqlClientIP, sc)
		}
		d := s.findDB(sc)
		if d == nil {
			continue
		}
		if o.allDatabases || databasesMode {
			fmt.Fprintf(&b, "\n--\n-- Current Database: `%s`\n--\n\n", sc)
			fmt.Fprintf(&b, "CREATE DATABASE /*!32312 IF NOT EXISTS*/ `%s` /*!40100 DEFAULT CHARACTER SET utf8mb4 */;\n\nUSE `%s`;\n", sc, sc)
		}
		for _, t := range d.Tables {
			if len(tableFilter) > 0 && !tableFilter[strings.ToLower(t.Name)] {
				continue
			}
			b.WriteString(dumpTable(&t, o.noData))
			if b.Len() > maxDumpBytes {
				b.WriteString("\n-- (dump truncated)\n")
				b.WriteString(dumpFooter())
				return b.String()
			}
		}
	}
	b.WriteString(dumpFooter())
	return b.String()
}

func schemasLabel(schemas []string) string {
	if len(schemas) == 1 {
		return schemas[0]
	}
	return ""
}

func dumpHeader(database string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "-- MySQL dump 10.13  Distrib %s, for Linux (x86_64)\n", mysqlClientVersion)
	b.WriteString("--\n")
	if database != "" {
		fmt.Fprintf(&b, "-- Host: %s    Database: %s\n", mysqlServerHostFQDN, database)
	} else {
		fmt.Fprintf(&b, "-- Host: %s    Database: \n", mysqlServerHostFQDN)
	}
	b.WriteString("-- ------------------------------------------------------\n")
	fmt.Fprintf(&b, "-- Server version\t%s\n\n", mysqlServerVersion)
	b.WriteString("/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n")
	b.WriteString("/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;\n")
	b.WriteString("/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;\n")
	b.WriteString("/*!50503 SET NAMES utf8mb4 */;\n")
	b.WriteString("/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;\n")
	b.WriteString("/*!40103 SET TIME_ZONE='+00:00' */;\n")
	b.WriteString("/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;\n")
	b.WriteString("/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;\n")
	b.WriteString("/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;\n")
	b.WriteString("/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;\n\n")
	return b.String()
}

func dumpFooter() string {
	var b strings.Builder
	b.WriteString("\n/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;\n\n")
	b.WriteString("/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;\n")
	b.WriteString("/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;\n")
	b.WriteString("/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;\n")
	b.WriteString("/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;\n")
	b.WriteString("/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;\n")
	b.WriteString("/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;\n")
	b.WriteString("/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;\n\n")
	fmt.Fprintf(&b, "-- Dump completed on %s\n", time.Now().Format("2006-01-02 15:04:05"))
	return b.String()
}

func dumpTable(t *Table, noData bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "--\n-- Table structure for table `%s`\n--\n\n", t.Name)
	fmt.Fprintf(&b, "DROP TABLE IF EXISTS `%s`;\n", t.Name)
	b.WriteString("/*!40101 SET @saved_cs_client     = @@character_set_client */;\n")
	b.WriteString("/*!50503 SET character_set_client = utf8mb4 */;\n")
	b.WriteString(createTableDDL(t) + ";\n")
	b.WriteString("/*!40101 SET character_set_client = @saved_cs_client */;\n\n")

	if noData || len(t.Rows) == 0 {
		fmt.Fprintf(&b, "--\n-- Dumping data for table `%s`\n--\n\n", t.Name)
		if len(t.Rows) == 0 {
			fmt.Fprintf(&b, "LOCK TABLES `%s` WRITE;\n/*!40000 ALTER TABLE `%s` DISABLE KEYS */;\n/*!40000 ALTER TABLE `%s` ENABLE KEYS */;\nUNLOCK TABLES;\n\n", t.Name, t.Name, t.Name)
		}
		if noData {
			return b.String()
		}
		if len(t.Rows) == 0 {
			return b.String()
		}
	}

	fmt.Fprintf(&b, "--\n-- Dumping data for table `%s`\n--\n\n", t.Name)
	fmt.Fprintf(&b, "LOCK TABLES `%s` WRITE;\n", t.Name)
	fmt.Fprintf(&b, "/*!40000 ALTER TABLE `%s` DISABLE KEYS */;\n", t.Name)
	fmt.Fprintf(&b, "INSERT INTO `%s` VALUES ", t.Name)
	for ri, row := range t.Rows {
		if ri > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('(')
		for ci := range t.Columns {
			if ci > 0 {
				b.WriteByte(',')
			}
			var v any
			if ci < len(row) {
				v = row[ci]
			}
			b.WriteString(dumpValue(v))
		}
		b.WriteByte(')')
	}
	b.WriteString(";\n")
	fmt.Fprintf(&b, "/*!40000 ALTER TABLE `%s` ENABLE KEYS */;\n", t.Name)
	b.WriteString("UNLOCK TABLES;\n\n")
	return b.String()
}

func dumpValue(v any) string {
	switch t := v.(type) {
	case nil:
		return "NULL"
	case int:
		return fmt.Sprintf("%d", t)
	case int64:
		return fmt.Sprintf("%d", t)
	case float64:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", t), "0"), ".")
	case string:
		return "'" + dumpEscape(t) + "'"
	case []byte:
		return "'" + dumpEscape(string(t)) + "'"
	default:
		return "'" + dumpEscape(fmt.Sprintf("%v", t)) + "'"
	}
}

func dumpEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\'':
			b.WriteString("\\'")
		case '\\':
			b.WriteString("\\\\")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case 0:
			b.WriteString("\\0")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
