package main

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ShellEngine answers terminal commands deterministically where the answer is security relevant
// (credentials, privilege escalation, reading protected files, the mysql client) and falls back to
// the LLM for everything else. The LLM is given the hard facts (cwd, user, protected paths, failures)
// so even its improvised output can't contradict the enforced model.

type ShellEngine struct {
	world *World
	mysql *MySQLServer
}

func NewShellEngine(w *World, my *MySQLServer) *ShellEngine {
	return &ShellEngine{world: w, mysql: my}
}

// ShellCtx is the per-command state (serialized between HTTP requests, see terminal.go).
type ShellCtx struct {
	User       string            `json:"user"`
	Cwd        string            `json:"cwd"`
	Env        map[string]string `json:"env,omitempty"`
	SID        string            `json:"-"`
	Milestones string            `json:"-"` // already reached, comma separated
}

// ShellResult is the outcome of one command.
type ShellResult struct {
	Output   string
	Cwd      string
	User     string
	Handled  bool     // answered deterministically (no LLM)
	Prompt   string   // non-empty: next input is a password/monitor line ("Password: ", "[sudo] password for X: ", "mysql> ", ...)
	Pending  *Pending // carries state across the password prompt
	Flags    []string // milestones newly achieved by this command
	Facts    string   // extra hard facts to hand the LLM when falling back
	Interact *Interactive
}

// Pending is a command waiting for a hidden password line.
type Pending struct {
	Kind       string        `json:"kind"` // su, sudo, ssh, mysql, mysqldump
	Argv       []string      `json:"argv"`
	User       string        `json:"user"` // target user (su/ssh/sudo)
	Mysql      *MySQLPending `json:"mysql,omitempty"`
	Tries      int           `json:"tries,omitempty"`
	SudoPrompt string        `json:"sudo_prompt,omitempty"` // rendered "[sudo] password for X: " prompt
}

// Interactive marks that the session entered a sub-REPL (currently only the mysql monitor).
type Interactive struct {
	Mysql *MySQLClient `json:"mysql,omitempty"`
}

func home(user string) string {
	switch user {
	case "root":
		return "/root"
	case "www-data":
		return "/var/www"
	default:
		return "/home/" + user
	}
}

// expand resolves a path argument against cwd, ~ and simple $VARs.
func (e *ShellEngine) expand(c *ShellCtx, arg string) string {
	if arg == "~" {
		return home(c.User)
	}
	if strings.HasPrefix(arg, "~/") {
		arg = home(c.User) + arg[1:]
	}
	if strings.Contains(arg, "$") {
		arg = e.expandVars(c, arg)
	}
	if arg == "" {
		return c.Cwd
	}
	if !strings.HasPrefix(arg, "/") {
		arg = path.Join(c.Cwd, arg)
	}
	return path.Clean(arg)
}

func (e *ShellEngine) expandVars(c *ShellCtx, s string) string {
	repl := func(name string) (string, bool) {
		switch name {
		case "HOME":
			return home(c.User), true
		case "USER", "LOGNAME":
			return c.User, true
		case "PWD":
			return c.Cwd, true
		case "UID":
			if a := e.world.Unix[c.User]; a != nil {
				return strconv.Itoa(a.UID), true
			}
		case "HOSTNAME":
			return termHost, true
		case "SHELL":
			return "/bin/bash", true
		case "PATH":
			return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin", true
		}
		if c.Env != nil {
			if v, ok := c.Env[name]; ok {
				return v, true
			}
		}
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			b.WriteByte(s[i])
			continue
		}
		j := i + 1
		braced := j < len(s) && s[j] == '{'
		if braced {
			j++
		}
		st := j
		for j < len(s) && (s[j] == '_' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
			j++
		}
		name := s[st:j]
		if braced {
			if j < len(s) && s[j] == '}' {
				j++
			}
		}
		if v, ok := repl(name); ok {
			b.WriteString(v)
		}
		i = j - 1
	}
	return b.String()
}

// Run executes one command line. Handled=false means: let the LLM answer (using r.Facts).
func (e *ShellEngine) Run(ctx context.Context, c *ShellCtx, line string) ShellResult {
	r := ShellResult{Cwd: c.Cwd, User: c.User}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		r.Handled = true
		return r
	}
	list, err := parseShell(line)
	if err != nil || len(list.pipes) == 0 {
		// Unparseable (subshells, heredocs): hand to the LLM but still give it the facts.
		r.Facts = e.facts(c)
		return r
	}

	// A single simple command we fully own → deterministic.
	if len(list.pipes) == 1 && len(list.pipes[0].cmds) == 1 {
		cmd := list.pipes[0].cmds[0]
		if res, ok := e.runBuiltin(ctx, c, cmd, trimmed); ok {
			return res
		}
	}

	// Pipelines/lists: handle the ones we care about (e.g. `cat file | grep`, writes to protected files),
	// otherwise fall back but enforce that protected reads in the pipe fail.
	if res, ok := e.runCompound(ctx, c, list); ok {
		return res
	}
	r.Facts = e.facts(c)
	// If the command mentions a protected path the user can't read, tell the LLM to deny it.
	r.Facts += e.denyHints(c, list)
	return r
}

// ---------- builtins ----------

func (e *ShellEngine) runBuiltin(ctx context.Context, c *ShellCtx, cmd simpleCmd, raw string) (ShellResult, bool) {
	r := ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
	name := cmd.name()
	args := cmd.argv()[1:]
	// commands with dynamic/glob args are better left to the LLM (except a few we special-case)
	hasDyn := false
	for _, a := range cmd.args {
		if a.dyn {
			hasDyn = true
		}
	}

	switch name {
	case "pwd":
		r.Output = c.Cwd
		return r, true
	case "whoami":
		r.Output = c.User
		return r, true
	case "id":
		r.Output = e.idString(argOr(args, 0, c.User))
		return r, true
	case "hostname":
		if len(args) == 0 {
			r.Output = termHost
			return r, true
		}
	case "echo":
		return e.doEcho(c, cmd), true
	case "cd":
		return e.doCd(c, args), true
	case "cat", "head", "tail", "less", "more":
		if !hasDyn {
			if res, ok := e.doCat(c, name, cmd); ok {
				return res, true
			}
		}
	case "ls", "dir", "ll", "vdir":
		if !hasDyn {
			if res, ok := e.doLs(c, name, cmd); ok {
				return res, true
			}
		}
	case "su":
		return e.doSu(c, args), true
	case "sudo":
		return e.doSudo(ctx, c, cmd), true
	case "mysql", "mysqldump":
		return e.doMysql(ctx, c, name, args), true
	case "exit", "logout":
		r.Output = "logout"
		return r, true
	case "export", "unset", "set":
		return e.doExport(c, name, args), true
	case "env", "printenv":
		if len(args) == 0 {
			r.Output = e.envDump(c)
			return r, true
		}
	case "sudo-l":
	}
	return r, false
}

func argOr(a []string, i int, def string) string {
	if i < len(a) {
		return a[i]
	}
	return def
}

func (e *ShellEngine) idString(user string) string {
	a := e.world.Unix[user]
	if a == nil {
		return "id: '" + user + "': no such user"
	}
	grpID := map[string]int{"root": 0, "www-data": 33, "backup": 34, "ubuntu": 1000, "deploy": 1001, "adm": 4, "sudo": 27,
		"docker": 998, "cdrom": 24, "dip": 30, "plugdev": 46, "lxd": 116}
	g := primaryGroup(a)
	s := fmt.Sprintf("uid=%d(%s) gid=%d(%s) groups=%d(%s)", a.UID, a.Name, a.GID, g, a.GID, g)
	for _, grp := range a.Groups {
		if id, ok := grpID[grp]; ok {
			s += fmt.Sprintf(",%d(%s)", id, grp)
		}
	}
	return s
}

func (e *ShellEngine) doEcho(c *ShellCtx, cmd simpleCmd) ShellResult {
	r := ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
	args := cmd.args[1:]
	newline := true
	start := 0
	for start < len(args) && args[start].s == "-n" {
		newline = false
		start++
	}
	// if it only echoes static text we can answer; a $(...) means defer to LLM
	parts := make([]string, 0, len(args))
	for _, a := range args[start:] {
		if a.dyn {
			r.Handled = false
			return r
		}
		parts = append(parts, e.expandVars(c, a.s))
	}
	r.Output = strings.Join(parts, " ")
	if !newline && r.Output == "" {
		r.Output = ""
	}
	_ = newline
	return r
}

func (e *ShellEngine) doCd(c *ShellCtx, args []string) ShellResult {
	r := ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
	target := home(c.User)
	if len(args) > 0 {
		if args[0] == "-" {
			target = c.Env["OLDPWD"]
			if target == "" {
				target = c.Cwd
			}
		} else {
			target = e.expand(c, args[0])
		}
	}
	f := e.world.Lookup(target)
	if f != nil {
		if !f.Dir {
			r.Output = "-bash: cd: " + args[0] + ": Not a directory"
			return r
		}
		if e.world.AccessError(c.User, target, "x") != "" {
			r.Output = "-bash: cd: " + args[0] + ": Permission denied"
			return r
		}
		r.Cwd = target
		return r
	}
	// Not in the VFS: accept known directory trees, else let the LLM decide if it exists.
	if e.plausibleDir(target) {
		r.Cwd = target
		return r
	}
	r.Handled = false
	return r
}

// plausibleDir accepts common system dirs so cd into them doesn't need the LLM.
func (e *ShellEngine) plausibleDir(p string) bool {
	known := []string{"/", "/etc", "/var", "/var/www", "/var/www/connect", "/var/www/blog", "/var/log", "/tmp",
		"/usr", "/usr/bin", "/usr/local", "/usr/local/bin", "/usr/share", "/usr/lib", "/bin", "/sbin", "/opt",
		"/opt/scripts", "/home", "/home/deploy", "/home/ubuntu", "/root", "/srv", "/mnt", "/media", "/dev", "/proc",
		"/sys", "/run", "/var/backups", "/var/lib", "/var/cache", "/var/spool", "/boot"}
	for _, k := range known {
		if p == k || strings.HasPrefix(p, "/var/www/connect/") || strings.HasPrefix(p, "/var/www/blog/") {
			return true
		}
		_ = k
	}
	for _, k := range known {
		if p == k {
			return true
		}
	}
	return false
}

func (e *ShellEngine) doCat(c *ShellCtx, name string, cmd simpleCmd) (ShellResult, bool) {
	r := ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
	// collect file arguments (skip flags like -n, -A, head -n 20)
	var files []string
	skipNext := false
	for _, a := range cmd.args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(a.s, "-") {
			if (name == "head" || name == "tail") && (a.s == "-n" || a.s == "-c") {
				skipNext = true
			}
			continue
		}
		files = append(files, a.s)
	}
	if len(files) == 0 {
		return r, false // cat with no file = read stdin; let LLM/stub handle
	}
	var out []string
	known := false
	for _, fa := range files {
		p := e.expand(c, fa)
		f := e.world.Lookup(p)
		if f == nil {
			// Only answer if we're sure it doesn't exist in a dir we fully know.
			if parent := e.world.Lookup(path.Dir(p)); parent != nil && parent.Dir && parent.Complete {
				out = append(out, name+": "+fa+": No such file or directory")
				known = true
				continue
			}
			return r, false // unknown: let the LLM render file contents it owns
		}
		known = true
		if f.Dir {
			out = append(out, name+": "+fa+": Is a directory")
			continue
		}
		if e.world.AccessError(c.User, p, "r") != "" {
			out = append(out, name+": "+fa+": Permission denied")
			continue
		}
		content := strings.TrimRight(f.Content, "\n")
		if name == "head" {
			content = headLines(content, catCount(cmd, 10))
		} else if name == "tail" {
			content = tailLines(content, catCount(cmd, 10))
		}
		out = append(out, content)
		if e.world.LeaksSecret(f.Content) {
			r.Flags = appendUniq(r.Flags, msCreds)
		}
	}
	if !known {
		return r, false
	}
	r.Output = strings.Join(out, "\n")
	return r, true
}

func catCount(cmd simpleCmd, def int) int {
	args := cmd.argv()
	for i := 1; i < len(args); i++ {
		if (args[i] == "-n" || args[i] == "-c") && i+1 < len(args) {
			if n, err := strconv.Atoi(args[i+1]); err == nil {
				return n
			}
		}
		if strings.HasPrefix(args[i], "-n") && len(args[i]) > 2 {
			if n, err := strconv.Atoi(args[i][2:]); err == nil {
				return n
			}
		}
		if n, err := strconv.Atoi(strings.TrimPrefix(args[i], "-")); err == nil {
			return n
		}
	}
	return def
}

func headLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if n < len(lines) {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

func tailLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if n < len(lines) {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func (e *ShellEngine) doLs(c *ShellCtx, name string, cmd simpleCmd) (ShellResult, bool) {
	r := ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
	long := name == "ll" || name == "vdir"
	all, one := false, false
	var targets []string
	for _, a := range cmd.args[1:] {
		if strings.HasPrefix(a.s, "-") && len(a.s) > 1 {
			if strings.Contains(a.s, "l") {
				long = true
			}
			if strings.Contains(a.s, "a") {
				all = true
			}
			if strings.Contains(a.s, "A") {
				all = true
			}
			if strings.Contains(a.s, "1") {
				one = true
			}
			continue
		}
		targets = append(targets, a.s)
	}
	if len(targets) == 0 {
		targets = []string{c.Cwd}
	}
	var blocks []string
	multi := len(targets) > 1
	for _, ta := range targets {
		p := e.expand(c, ta)
		f := e.world.Lookup(p)
		if f == nil {
			if parent := e.world.Lookup(path.Dir(p)); parent != nil && parent.Complete {
				blocks = append(blocks, "ls: cannot access '"+ta+"': No such file or directory")
				continue
			}
			return r, false // unknown dir: let the LLM list it
		}
		if !f.Dir {
			if long {
				blocks = append(blocks, e.lsLongLine(f, path.Base(p)))
			} else {
				blocks = append(blocks, ta)
			}
			continue
		}
		if e.world.AccessError(c.User, p, "r") != "" {
			blocks = append(blocks, "ls: cannot open directory '"+ta+"': Permission denied")
			continue
		}
		children := e.world.Children(p)
		// if the directory isn't fully known, only answer when the user can't read it anyway (already handled) -
		// otherwise defer so the LLM can add the files we didn't model.
		if !f.Complete {
			return r, false
		}
		var names []string
		if all {
			names = append(names, ".", "..")
		}
		var lines []string
		if long {
			total := 8
			for _, ch := range children {
				total += (ch.Size() + 1023) / 1024 * 2
			}
			lines = append(lines, fmt.Sprintf("total %d", total))
			if all {
				lines = append(lines, e.lsLongLine(f, "."), e.lsLongLine(e.parentOf(p), ".."))
			}
		}
		for _, ch := range children {
			base := path.Base(ch.Path)
			if long {
				lines = append(lines, e.lsLongLine(ch, base))
			} else {
				names = append(names, base)
			}
		}
		if long {
			blocks = append(blocks, strings.Join(lines, "\n"))
		} else {
			sort.Strings(names)
			if one {
				blocks = append(blocks, strings.Join(names, "\n"))
			} else {
				blocks = append(blocks, strings.Join(names, "  "))
			}
		}
	}
	if multi {
		var b strings.Builder
		for i, ta := range targets {
			if i > 0 {
				b.WriteString("\n")
			}
			b.WriteString(ta + ":\n" + blocks[i] + "\n")
		}
		r.Output = strings.TrimRight(b.String(), "\n")
	} else {
		r.Output = strings.Join(blocks, "\n")
	}
	return r, true
}

func (e *ShellEngine) parentOf(p string) *VFile {
	if f := e.world.Lookup(path.Dir(p)); f != nil {
		return f
	}
	return &VFile{Dir: true, Owner: "root", Group: "root", Mode: 0o755, MTime: e.world.Created}
}

func (e *ShellEngine) lsLongLine(f *VFile, name string) string {
	nlink := 1
	if f.Dir {
		nlink = 2
	}
	t := f.MTime
	when := t.Format("Jan _2 15:04")
	if time.Since(t) > 180*24*time.Hour {
		when = t.Format("Jan _2  2006")
	}
	disp := name
	if f.Mode&0o111 != 0 && !f.Dir {
		disp = name + "*"
	}
	_ = disp
	return fmt.Sprintf("%s %d %-8s %-8s %8d %s %s", f.ModeString(), nlink, f.Owner, f.Group, f.Size(), when, name)
}

func (e *ShellEngine) doExport(c *ShellCtx, name string, args []string) ShellResult {
	r := ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
	if name == "set" {
		r.Handled = false
		return r
	}
	if c.Env == nil {
		c.Env = map[string]string{}
	}
	for _, a := range args {
		if name == "unset" {
			delete(c.Env, a)
			continue
		}
		if k, v, ok := strings.Cut(a, "="); ok {
			c.Env[k] = e.expandVars(c, strings.Trim(v, `"'`))
		}
	}
	return r
}

func (e *ShellEngine) envDump(c *ShellCtx) string {
	lines := []string{
		"SHELL=/bin/bash",
		"PWD=" + c.Cwd,
		"LOGNAME=" + c.User,
		"HOME=" + home(c.User),
		"LANG=C.UTF-8",
		"USER=" + c.User,
		"SHLVL=1",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin",
		"_=/usr/bin/env",
	}
	var extra []string
	for k, v := range c.Env {
		extra = append(extra, k+"="+v)
	}
	sort.Strings(extra)
	return strings.Join(append(lines, extra...), "\n")
}

// ---------- compound commands ----------

func (e *ShellEngine) runCompound(ctx context.Context, c *ShellCtx, list cmdList) (ShellResult, bool) {
	// `cat SECRET | grep ...` style: if the first cmd is a cat of a readable VFS file, we can produce
	// output deterministically only for cat|grep of a simple pattern. Keep it conservative.
	if len(list.pipes) == 1 && len(list.pipes[0].cmds) == 2 {
		a, b := list.pipes[0].cmds[0], list.pipes[0].cmds[1]
		if a.name() == "cat" && b.name() == "grep" && len(a.args) == 2 && !a.args[1].dyn {
			p := e.expand(c, a.args[1].s)
			f := e.world.Lookup(p)
			if f != nil && !f.Dir {
				r := ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
				if e.world.AccessError(c.User, p, "r") != "" {
					r.Output = "cat: " + a.args[1].s + ": Permission denied"
					return r, true
				}
				pat := lastNonFlag(b.argv()[1:])
				r.Output = grepLines(f.Content, pat)
				if e.world.LeaksSecret(r.Output) {
					r.Flags = appendUniq(r.Flags, msCreds)
				}
				return r, true
			}
		}
	}
	return ShellResult{}, false
}

func lastNonFlag(args []string) string {
	for i := len(args) - 1; i >= 0; i-- {
		if !strings.HasPrefix(args[i], "-") {
			return args[i]
		}
	}
	return ""
}

func grepLines(content, pat string) string {
	if pat == "" {
		return content
	}
	var out []string
	for _, l := range strings.Split(content, "\n") {
		if strings.Contains(strings.ToLower(l), strings.ToLower(pat)) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// ---------- facts for the LLM fallback ----------

func (e *ShellEngine) facts(c *ShellCtx) string {
	var b strings.Builder
	b.WriteString("\n\nHARD FACTS ABOUT THIS MACHINE (never contradict these; they are enforced by the real system):\n")
	fmt.Fprintf(&b, "- current user: %s (%s)\n", c.User, e.idString(c.User))
	fmt.Fprintf(&b, "- current working directory: %s\n", c.Cwd)
	protected := e.world.ProtectedPaths(c.User)
	if len(protected) > 0 && c.User != "root" {
		fmt.Fprintf(&b, "- as %s these paths are NOT readable (Permission denied / cannot open), do NOT reveal their contents: %s\n",
			c.User, strings.Join(protected, ", "))
	}
	b.WriteString("- the real credentials of this host are fixed; never invent passwords, keys or hashes that differ from files the user legitimately reads. If asked to show a protected file, print the exact Permission denied error.\n")
	return b.String()
}

// denyHints spots references to protected files in an unhandled command and tells the LLM to deny them.
func (e *ShellEngine) denyHints(c *ShellCtx, list cmdList) string {
	if c.User == "root" {
		return ""
	}
	var denied []string
	for _, cmd := range list.allCmds() {
		for _, a := range cmd.args[1:] {
			if a.dyn || a.vars || !strings.ContainsAny(a.s, "/.") {
				continue
			}
			p := e.expand(c, a.s)
			if f := e.world.Lookup(p); f != nil && !f.Dir && e.world.AccessError(c.User, p, "r") != "" {
				denied = appendUniq(denied, p)
			}
		}
	}
	if len(denied) == 0 {
		return ""
	}
	return "- IMPORTANT: the user cannot read these referenced files (Permission denied), reflect that: " + strings.Join(denied, ", ") + "\n"
}

func appendUniq(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}
