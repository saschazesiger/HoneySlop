// Package web holds the embedded frontends: the fake terminal on / and the /pot dashboard.
package web

import "embed"

//go:embed terminal/index.html
var TerminalHTML string

//go:embed pot
var Pot embed.FS
