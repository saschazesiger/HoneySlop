package main

// Shared types of the simulated MySQL server (data in worlddata.go, engine in mysqlsim.go).

// Database is one MySQL schema of the world.
type Database struct {
	Name   string
	Tables []Table
}

// Table is a MySQL table definition plus its rows.
type Table struct {
	Name          string
	Engine        string // InnoDB (default) / MyISAM
	Comment       string
	Columns       []Column
	Rows          [][]any // per row one value per column: nil (NULL), int, int64, float64 or string (dates as "2006-01-02 15:04:05")
	AutoIncrement int64   // next AUTO_INCREMENT value (0 = none)
}

// Column is a MySQL column as shown by DESCRIBE.
type Column struct {
	Name     string
	Type     string // MySQL column type, e.g. "bigint(20) unsigned", "varchar(255)", "timestamp", "enum('a','b')"
	Nullable bool
	Key      string  // "", "PRI", "UNI", "MUL"
	Default  *string // nil = NULL / none
	Extra    string  // "auto_increment", "on update CURRENT_TIMESTAMP", ...
}
