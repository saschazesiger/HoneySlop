package main

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// mysqlInstance is one isolated in-memory SQLite database loaded with the world
// data visible to a single MySQL account. Terminal sessions each own a writable
// instance; the web view keeps one shared snapshot per account.
type mysqlInstance struct {
	db    *sql.DB
	acct  *MySQLAccount
	user  string
	host  string
	built bool
}

var instSeq int64

// getSessionInstance returns (creating if needed) the writable instance for a
// terminal session, LRU-bounded to maxSessions.
func (s *MySQLServer) getSessionInstance(sid string, acct *MySQLAccount, host string) (*mysqlInstance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if inst, ok := s.sessions[sid]; ok {
		// bump LRU
		for i, id := range s.order {
			if id == sid {
				s.order = append(s.order[:i], s.order[i+1:]...)
				break
			}
		}
		s.order = append(s.order, sid)
		return inst, nil
	}
	inst, err := s.buildInstance(acct, host)
	if err != nil {
		return nil, err
	}
	s.sessions[sid] = inst
	s.order = append(s.order, sid)
	for len(s.order) > maxSessions {
		old := s.order[0]
		s.order = s.order[1:]
		if oi, ok := s.sessions[old]; ok {
			_ = oi.db.Close()
			delete(s.sessions, old)
		}
	}
	return inst, nil
}

// getWebInstance returns (creating if needed) the shared snapshot for an account.
func (s *MySQLServer) getWebInstance(acct *MySQLAccount, host string) (*mysqlInstance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := acct.User
	if inst, ok := s.web[key]; ok {
		return inst, nil
	}
	inst, err := s.buildInstance(acct, host)
	if err != nil {
		return nil, err
	}
	s.web[key] = inst
	return inst, nil
}

// buildInstance creates a fresh in-memory database for an account.
func (s *MySQLServer) buildInstance(acct *MySQLAccount, host string) (*mysqlInstance, error) {
	n := atomic.AddInt64(&instSeq, 1)
	// A private, process-unique shared-cache name keeps the data alive across
	// the pool while remaining isolated from other instances.
	dsn := fmt.Sprintf("file:mysqlsim_%d?mode=memory&cache=shared", n)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // single connection owns the in-memory schema
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	inst := &mysqlInstance{db: db, acct: acct, host: host}
	if acct != nil {
		inst.user = acct.User
	}

	schemas := s.visibleSchemas(acct)
	for _, sc := range schemas {
		if strings.EqualFold(sc, "information_schema") {
			continue // created last, from the others
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf("ATTACH DATABASE ':memory:' AS %s", quoteIdent(sc))); err != nil {
			return nil, err
		}
		if d := s.findDB(sc); d != nil {
			if err := loadSchema(ctx, db, d); err != nil {
				return nil, err
			}
		}
	}
	if err := s.buildInformationSchema(ctx, db, acct, schemas); err != nil {
		return nil, err
	}
	inst.built = true
	return inst, nil
}

// loadSchema creates and fills the tables of one data schema.
func loadSchema(ctx context.Context, db *sql.DB, d *Database) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range d.Tables {
		cols := make([]string, len(t.Columns))
		for i, c := range t.Columns {
			cols[i] = quoteIdent(c.Name) // typeless column keeps values verbatim
		}
		create := fmt.Sprintf("CREATE TABLE %s.%s (%s)", quoteIdent(d.Name), quoteIdent(t.Name), strings.Join(cols, ", "))
		if _, err := tx.ExecContext(ctx, create); err != nil {
			return err
		}
		if len(t.Columns) == 0 {
			continue
		}
		ph := strings.TrimSuffix(strings.Repeat("?, ", len(t.Columns)), ", ")
		ins := fmt.Sprintf("INSERT INTO %s.%s VALUES (%s)", quoteIdent(d.Name), quoteIdent(t.Name), ph)
		stmt, err := tx.PrepareContext(ctx, ins)
		if err != nil {
			return err
		}
		for _, row := range t.Rows {
			args := make([]any, len(t.Columns))
			for i := range t.Columns {
				if i < len(row) {
					args[i] = row[i]
				}
			}
			if _, err := stmt.ExecContext(ctx, args...); err != nil {
				stmt.Close()
				return err
			}
		}
		stmt.Close()
	}
	return tx.Commit()
}

// ---- information_schema synthesis (filtered to visible schemas) ----

func (s *MySQLServer) buildInformationSchema(ctx context.Context, db *sql.DB, acct *MySQLAccount, schemas []string) error {
	if _, err := db.ExecContext(ctx, "ATTACH DATABASE ':memory:' AS information_schema"); err != nil {
		return err
	}
	stmts := []string{
		`CREATE TABLE information_schema.SCHEMATA (CATALOG_NAME, SCHEMA_NAME, DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME, SQL_PATH)`,
		`CREATE TABLE information_schema.TABLES (TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, ENGINE, VERSION, ROW_FORMAT, TABLE_ROWS, AVG_ROW_LENGTH, DATA_LENGTH, AUTO_INCREMENT, TABLE_COLLATION, TABLE_COMMENT)`,
		`CREATE TABLE information_schema.COLUMNS (TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION, COLUMN_DEFAULT, IS_NULLABLE, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, COLUMN_TYPE, COLUMN_KEY, EXTRA, PRIVILEGES, COLUMN_COMMENT)`,
	}
	for _, q := range stmts {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, sc := range schemas {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO information_schema.SCHEMATA VALUES ('def', ?, 'utf8mb4', 'utf8mb4_unicode_ci', NULL)`, sc); err != nil {
			return err
		}
		d := s.findDB(sc)
		if d == nil {
			continue
		}
		for _, t := range d.Tables {
			eng := t.Engine
			if eng == "" {
				eng = "InnoDB"
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO information_schema.TABLES VALUES ('def', ?, ?, 'BASE TABLE', ?, 10, 'Dynamic', ?, 0, 16384, ?, 'utf8mb4_unicode_ci', ?)`,
				sc, t.Name, eng, len(t.Rows), nullableAutoInc(t.AutoIncrement), t.Comment); err != nil {
				return err
			}
			for i, c := range t.Columns {
				isNull := "NO"
				if c.Nullable {
					isNull = "YES"
				}
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO information_schema.COLUMNS VALUES ('def', ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, 'select,insert,update,references', '')`,
					sc, t.Name, c.Name, i+1, colDefault(c.Default), isNull, dataTypeOf(c.Type), c.Type, c.Key, c.Extra); err != nil {
					return err
				}
			}
		}
	}
	return tx.Commit()
}

func nullableAutoInc(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func colDefault(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// dataTypeOf extracts the bare DATA_TYPE from a COLUMN_TYPE ("bigint(20) unsigned" -> "bigint").
func dataTypeOf(colType string) string {
	t := strings.TrimSpace(strings.ToLower(colType))
	if i := strings.IndexAny(t, "( "); i >= 0 {
		t = t[:i]
	}
	return t
}

// ---- identifier / value helpers ----

var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]*$`)

func quoteIdent(s string) string {
	return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
}

// rawToStr converts a scanned driver value to the display pointer (nil = NULL).
func rawToStr(v any) *string {
	if v == nil {
		return nil
	}
	var s string
	switch t := v.(type) {
	case []byte:
		s = string(t)
	case string:
		s = t
	case int64:
		s = fmt.Sprintf("%d", t)
	case float64:
		s = strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", t), "0"), ".")
	case bool:
		if t {
			s = "1"
		} else {
			s = "0"
		}
	case time.Time:
		s = t.Format("2006-01-02 15:04:05")
	default:
		s = fmt.Sprintf("%v", t)
	}
	return &s
}
