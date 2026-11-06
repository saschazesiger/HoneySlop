package main

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func sp(s string) *string { return &s }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// firstKeyword returns the lower-cased leading keyword of a statement.
func firstKeyword(q string) string {
	q = strings.TrimSpace(q)
	i := 0
	for i < len(q) && !isSpace(q[i]) && q[i] != '(' {
		i++
	}
	return strings.ToLower(q[:i])
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }

var writeKeywords = map[string]bool{
	"insert": true, "update": true, "delete": true, "replace": true,
	"create": true, "drop": true, "alter": true, "truncate": true,
	"grant": true, "revoke": true, "rename": true, "load": true, "call": true,
}

func isWrite(kw string) bool { return writeKeywords[kw] }

// isSchemaKeyword filters obvious non-schema identifiers before a dot.
func isSchemaKeyword(s string) bool {
	switch strings.ToLower(s) {
	case "a", "b", "c", "t", "t1", "t2", "x", "u":
		return true // common table aliases, never schema names
	}
	return false
}

var fromClauseRe = regexp.MustCompile(`(?i)\b(from|join|into)\b`)

// referencesTable reports whether a statement reads/writes a table object.
func referencesTable(q string) bool {
	kw := firstKeyword(q)
	switch kw {
	case "update", "delete", "insert", "replace", "truncate":
		return true
	}
	return fromClauseRe.MatchString(q)
}

var tableAfterRe = regexp.MustCompile("(?i)\\b(?:from|into|update|join)\\s+`?([A-Za-z_][A-Za-z0-9_$]*)`?(?:\\s*\\.\\s*`?([A-Za-z_][A-Za-z0-9_$]*)`?)?")

// firstTableName extracts a best-effort table name from a statement (for error text).
func firstTableName(q string) string {
	m := tableAfterRe.FindStringSubmatch(q)
	if m == nil {
		return ""
	}
	if m[2] != "" {
		return m[2]
	}
	return m[1]
}

// resolveTable parses a "db.table" / "table" token, qualifying bare names with curDB.
func (ec *execCtx) resolveTable(tok string) (schema, table string) {
	tok = strings.TrimSpace(tok)
	tok = strings.SplitN(tok, " ", 2)[0]
	parts := strings.SplitN(tok, ".", 2)
	if len(parts) == 2 {
		schema = canonicalSchema(ec.srv, strings.Trim(parts[0], "`\"'"))
		table = strings.Trim(parts[1], "`\"'")
		return
	}
	table = strings.Trim(parts[0], "`\"'")
	schema = ec.curDB
	return
}

func findTable(d *Database, name string) *Table {
	for i := range d.Tables {
		if strings.EqualFold(d.Tables[i].Name, name) {
			return &d.Tables[i]
		}
	}
	return nil
}

// cutPrefixFold returns the remainder after prefix (case-insensitive), or ""
// if s does not start with prefix.
func cutPrefixFold(s, prefix string) string {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):]
	}
	return ""
}

// trimPrefixFold strips prefix (case-insensitive) if present, else returns s.
func trimPrefixFold(s, prefix string) string {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):]
	}
	return s
}

func firstToken(s string) (tok, rest string) {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && !isSpace(s[i]) {
		i++
	}
	return s[:i], strings.TrimSpace(s[i:])
}

func firstFieldBefore(s string, sep byte) string {
	if i := strings.IndexByte(s, sep); i >= 0 {
		return s[:i]
	}
	return s
}

// cutFromClause removes a trailing "FROM db" / "IN db" from rest and returns db.
func cutFromClause(rest *string) string {
	m := regexp.MustCompile(`(?i)\b(?:from|in)\s+` + "`?" + `([A-Za-z_][A-Za-z0-9_$]*)` + "`?").FindStringSubmatchIndex(*rest)
	if m == nil {
		return ""
	}
	db := (*rest)[m[2]:m[3]]
	*rest = strings.TrimSpace((*rest)[:m[0]] + (*rest)[m[1]:])
	return db
}

var likeClauseRe = regexp.MustCompile(`(?i)\blike\s+'([^']*)'`)

func parseLike(rest string) string {
	m := likeClauseRe.FindStringSubmatch(rest)
	if m == nil {
		return ""
	}
	return m[1]
}

// likeMatch implements SQL LIKE with % and _ wildcards (case-insensitive).
func likeMatch(pattern, s string) bool {
	var b strings.Builder
	b.WriteString("(?is)^")
	for _, r := range pattern {
		switch r {
		case '%':
			b.WriteString(".*")
		case '_':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

func hasFromClause(s string) bool { return fromClauseRe.MatchString(s) }

func sqlQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func unquoteSQL(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		inner := s[1 : len(s)-1]
		q := string(s[0])
		return strings.ReplaceAll(inner, q+q, q)
	}
	return s
}

func syntaxNear(near string) string {
	near = strings.TrimSpace(near)
	if len(near) > 80 {
		near = near[:80]
	}
	return "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '" + near + "' at line 1"
}

// splitAlias splits "expr AS alias" / "expr alias" into (expr, alias).
func splitAlias(raw string) (expr, alias string) {
	raw = strings.TrimSpace(raw)
	if idx := regexp.MustCompile(`(?i)\s+as\s+`).FindStringIndex(raw); idx != nil {
		return strings.TrimSpace(raw[:idx[0]]), strings.Trim(strings.TrimSpace(raw[idx[1]:]), "`\"'")
	}
	return raw, ""
}

// splitTopLevel splits s on sep respecting quotes, backticks and parentheses.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	var cur strings.Builder
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			cur.WriteByte(c)
			if c == quote {
				if i+1 < len(s) && s[i+1] == quote {
					cur.WriteByte(s[i+1])
					i++
				} else {
					quote = 0
				}
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
			cur.WriteByte(c)
		case '(':
			depth++
			cur.WriteByte(c)
		case ')':
			if depth > 0 {
				depth--
			}
			cur.WriteByte(c)
		case sep:
			if depth == 0 {
				out = append(out, cur.String())
				cur.Reset()
			} else {
				cur.WriteByte(c)
			}
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}

// splitStatements splits a script into statements on top-level ';', handling
// quotes, backticks and -- / # / /* */ comments.
func splitStatements(s string) []string {
	var out []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			cur.WriteByte(c)
			if c == quote {
				if i+1 < len(s) && s[i+1] == quote {
					cur.WriteByte(s[i+1])
					i++
				} else {
					quote = 0
				}
			}
			continue
		}
		switch {
		case c == '\'' || c == '"' || c == '`':
			quote = c
			cur.WriteByte(c)
		case c == '-' && i+2 < len(s) && s[i+1] == '-' && (s[i+2] == ' ' || s[i+2] == '\t'):
			for i < len(s) && s[i] != '\n' {
				i++
			}
			cur.WriteByte('\n')
		case c == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			cur.WriteByte('\n')
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			// keep /*! ... */ versioned comments verbatim (content matters)
			versioned := i+2 < len(s) && s[i+2] == '!'
			j := i + 2
			for j+1 < len(s) && !(s[j] == '*' && s[j+1] == '/') {
				j++
			}
			if versioned {
				cur.WriteString(s[i : j+2])
			}
			i = j + 1
		case c == ';':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	return out
}

// ---- SQLite error -> MySQL error mapping ----

var (
	errNoTable  = regexp.MustCompile(`no such table: (?:main\.)?([A-Za-z0-9_$.]+)`)
	errNoCol    = regexp.MustCompile(`no such column: ([A-Za-z0-9_$.]+)`)
	errNoColIns = regexp.MustCompile(`table .* has no column named ([A-Za-z0-9_$]+)`)
	errNoFunc   = regexp.MustCompile(`no such function: ([A-Za-z0-9_$]+)`)
	errAmbig    = regexp.MustCompile(`ambiguous column name: ([A-Za-z0-9_$.]+)`)
)

func (ec *execCtx) mapError(err error, q string) *MySQLError {
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "interrupted") || err == context.DeadlineExceeded || strings.Contains(low, "context deadline"):
		return myErr(1317, "70100", "Query execution was interrupted")
	case errNoTable.MatchString(msg):
		name := errNoTable.FindStringSubmatch(msg)[1]
		if !strings.Contains(name, ".") && ec.curDB != "" {
			name = ec.curDB + "." + name
		}
		return myErr(1146, "42S02", "Table '%s' doesn't exist", name)
	case errNoColIns.MatchString(msg):
		return myErr(1054, "42S22", "Unknown column '%s' in 'field list'", errNoColIns.FindStringSubmatch(msg)[1])
	case errNoCol.MatchString(msg):
		col := errNoCol.FindStringSubmatch(msg)[1]
		return myErr(1054, "42S22", "Unknown column '%s' in '%s'", col, clauseForColumn(q))
	case errAmbig.MatchString(msg):
		return myErr(1052, "23000", "Column '%s' in field list is ambiguous", errAmbig.FindStringSubmatch(msg)[1])
	case errNoFunc.MatchString(msg):
		fn := errNoFunc.FindStringSubmatch(msg)[1]
		db := ec.curDB
		if db == "" {
			db = "veltrona_connect"
		}
		return myErr(1305, "42000", "FUNCTION %s.%s does not exist", db, fn)
	case strings.Contains(low, "unique constraint failed"):
		return myErr(1062, "23000", "Duplicate entry for key")
	case strings.Contains(low, "do not have the same number of result columns"),
		strings.Contains(low, "selects to the left and right"):
		return myErr(1222, "21000", "The used SELECT statements have a different number of columns")
	case strings.Contains(low, "syntax error"), strings.Contains(low, "unrecognized token"),
		strings.Contains(low, "incomplete input"), strings.Contains(low, "near \""):
		return myErrLit(1064, "42000", syntaxNear(nearToken(msg, q)))
	}
	// Unknown / unsupported syntax: present as a generic MySQL syntax error.
	return myErrLit(1064, "42000", syntaxNear(firstKeyword(q)))
}

// clauseForColumn guesses which clause an unknown column error belongs to.
func clauseForColumn(q string) string {
	low := strings.ToLower(q)
	switch {
	case strings.Contains(low, "order by"):
		return "order clause"
	case strings.Contains(low, "group by"):
		return "group statement"
	case strings.Contains(low, "where"):
		return "where clause"
	case strings.Contains(low, "having"):
		return "having clause"
	}
	return "field list"
}

var nearQuoteRe = regexp.MustCompile(`near "([^"]*)"`)

func nearToken(msg, q string) string {
	if m := nearQuoteRe.FindStringSubmatch(msg); m != nil && m[1] != "" {
		idx := strings.Index(q, m[1])
		if idx >= 0 {
			tail := q[idx:]
			if len(tail) > 80 {
				tail = tail[:80]
			}
			return tail
		}
		return m[1]
	}
	return firstKeyword(q)
}

// ---- classic mysql table formatter ----

func FormatMySQLTable(r *SQLResult) string {
	if r == nil {
		return ""
	}
	secs := fmt.Sprintf("%.2f", r.Elapsed.Seconds())
	if !r.IsSet {
		if r.Info == "Database changed" {
			return "Database changed\n"
		}
		noun := "rows"
		if r.Affected == 1 {
			noun = "row"
		}
		out := fmt.Sprintf("Query OK, %d %s affected (%s sec)\n", r.Affected, noun, secs)
		if r.Info != "" {
			out += r.Info + "\n"
		}
		return out
	}
	// result set
	n := len(r.Columns)
	widths := make([]int, n)
	for i, c := range r.Columns {
		widths[i] = len(c)
	}
	cell := func(p *string) string {
		if p == nil {
			return "NULL"
		}
		return *p
	}
	for _, row := range r.Rows {
		for i := 0; i < n && i < len(row); i++ {
			if l := len(cell(row[i])); l > widths[i] {
				widths[i] = l
			}
		}
	}
	var b strings.Builder
	sep := func() {
		b.WriteByte('+')
		for _, w := range widths {
			b.WriteString(strings.Repeat("-", w+2))
			b.WriteByte('+')
		}
		b.WriteByte('\n')
	}
	writeRow := func(vals []string) {
		b.WriteByte('|')
		for i, w := range widths {
			v := ""
			if i < len(vals) {
				v = vals[i]
			}
			b.WriteByte(' ')
			b.WriteString(v)
			b.WriteString(strings.Repeat(" ", w-len(v)))
			b.WriteString(" |")
		}
		b.WriteByte('\n')
	}
	if n == 0 || len(r.Rows) == 0 {
		return "Empty set (" + secs + " sec)\n"
	}
	sep()
	writeRow(r.Columns)
	sep()
	for _, row := range r.Rows {
		vals := make([]string, n)
		for i := 0; i < n; i++ {
			if i < len(row) {
				vals[i] = cell(row[i])
			}
		}
		writeRow(vals)
	}
	sep()
	noun := "rows"
	if len(r.Rows) == 1 {
		noun = "row"
	}
	fmt.Fprintf(&b, "%d %s in set (%s sec)\n", len(r.Rows), noun, secs)
	return b.String()
}
