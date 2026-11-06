package main

import (
	"context"
	"fmt"
	"strings"
)

// Milestone keys (kill chain).
const (
	msCreds = "creds" // real secret obtained
	msDB    = "db"    // database access with real credentials
	msLogin = "login" // logged into a web app with real credentials
	msUser  = "user"  // shell as the deploy user (lateral movement)
	msRoot  = "root"  // root shell
)

var milestoneOrder = []string{msCreds, msDB, msLogin, msUser, msRoot}

// ---------- su ----------

func (e *ShellEngine) doSu(c *ShellCtx, args []string) ShellResult {
	r := ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
	target := "root"
	login := false
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-" || a == "-l" || a == "--login":
			login = true
		case a == "-c":
			// su -c 'cmd': we don't execute the inner command deterministically
			r.Handled = false
			return r
		case strings.HasPrefix(a, "-"):
			// ignore other flags (-s, -m, ...)
		default:
			target = a
			rest = args[i+1:]
			_ = rest
			i = len(args)
		}
	}
	acc := e.world.Unix[target]
	if acc == nil {
		r.Output = "su: user " + target + " does not exist or the user entry does not contain all the required fields"
		return r
	}
	// root never needs a password to switch user
	if c.User == "root" {
		r.User = target
		if login {
			r.Cwd = acc.Home
		}
		return r
	}
	if acc.Password == "" {
		// locked account: prompt then always fail
		r.Prompt = "Password: "
		r.Pending = &Pending{Kind: "su", User: target, Argv: args}
		return r
	}
	r.Prompt = "Password: "
	r.Pending = &Pending{Kind: "su", User: target, Argv: args}
	return r
}

// ContinueSu handles the password line for su.
func (e *ShellEngine) continueSu(c *ShellCtx, p *Pending, password string) ShellResult {
	r := ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
	login := false
	for _, a := range p.Argv {
		if a == "-" || a == "-l" || a == "--login" {
			login = true
		}
	}
	if e.world.CheckUnix(p.User, password) {
		r.User = p.User
		if login {
			if acc := e.world.Unix[p.User]; acc != nil {
				r.Cwd = acc.Home
			}
		}
		r.Flags = e.escalationFlags(c, p.User)
		return r
	}
	r.Output = "su: Authentication failure"
	return r
}

// escalationFlags returns the milestones reached by becoming newUser.
func (e *ShellEngine) escalationFlags(c *ShellCtx, newUser string) []string {
	var f []string
	switch newUser {
	case "root":
		f = append(f, msRoot)
	case "deploy":
		f = append(f, msUser)
	}
	return f
}

// ---------- sudo ----------

func (e *ShellEngine) doSudo(ctx context.Context, c *ShellCtx, cmd simpleCmd) ShellResult {
	r := ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
	args := cmd.argv()[1:]
	// parse a few sudo flags
	runAs := "root"
	listMode := false
	nonInteractive := false
	cmdStart := len(args)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-l" || a == "--list":
			listMode = true
		case a == "-n":
			nonInteractive = true
		case a == "-k" || a == "-K", a == "-i", a == "-s", a == "-H", a == "-E", a == "-b":
			// flags that take no command argument we care about
		case a == "-u" || a == "--user":
			if i+1 < len(args) {
				runAs = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "-u"):
			runAs = a[2:]
		case strings.HasPrefix(a, "--user="):
			runAs = a[len("--user="):]
		case strings.HasPrefix(a, "-"):
			// unknown flag, ignore
		default:
			cmdStart = i
			i = len(args) // stop: the rest is the command
		}
	}
	inner := []string{}
	if cmdStart < len(args) {
		inner = args[cmdStart:]
	}

	sudoAllowed, nopasswd := e.sudoRights(c.User)

	if listMode {
		r.Output = e.sudoList(c.User, sudoAllowed, nopasswd)
		return r
	}
	if len(inner) == 0 {
		r.Handled = false
		return r
	}

	// deploy has NOPASSWD for two specific systemctl commands only.
	full := strings.Join(inner, " ")
	if np := e.matchNopasswd(c.User, full); np {
		return e.runSudoCommand(ctx, c, runAs, inner, false) // NOPASSWD whitelist: a service command, not a root shell
	}

	if !sudoAllowed {
		if nonInteractive {
			r.Output = "sudo: a password is required"
			return r
		}
		// prompt once, then deny with the real "not in sudoers" message
		r.Prompt = fmt.Sprintf("[sudo] password for %s: ", c.User)
		r.Pending = &Pending{Kind: "sudo", User: runAs, Argv: inner}
		return r
	}
	// user is a sudoer (ubuntu): needs their own password
	if nonInteractive {
		r.Output = "sudo: a password is required"
		return r
	}
	r.Prompt = fmt.Sprintf("[sudo] password for %s: ", c.User)
	r.Pending = &Pending{Kind: "sudo", User: runAs, Argv: inner}
	return r
}

func (e *ShellEngine) continueSudo(ctx context.Context, c *ShellCtx, p *Pending, password string) ShellResult {
	r := ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
	sudoAllowed, _ := e.sudoRights(c.User)
	if !sudoAllowed {
		// authenticate the user's own password just like sudo does, then refuse.
		if e.world.CheckUnix(c.User, password) || p.Tries >= 2 {
			r.Output = fmt.Sprintf("%s is not in the sudoers file.  This incident will be reported.", c.User)
			return r
		}
		r.Output = "Sorry, try again."
		r.Prompt = fmt.Sprintf("[sudo] password for %s: ", c.User)
		np := *p
		np.Tries++
		r.Pending = &np
		return r
	}
	if !e.world.CheckUnix(c.User, password) {
		if p.Tries >= 2 {
			r.Output = "sudo: 3 incorrect password attempts"
			return r
		}
		r.Output = "Sorry, try again."
		r.Prompt = fmt.Sprintf("[sudo] password for %s: ", c.User)
		np := *p
		np.Tries++
		r.Pending = &np
		return r
	}
	return e.runSudoCommand(ctx, c, p.User, p.Argv, true)
}

// runSudoCommand runs the inner command as runAs. Interactive shells / escalation are handled here;
// other commands fall back to the LLM but with the elevated user baked into the facts.
func (e *ShellEngine) runSudoCommand(ctx context.Context, c *ShellCtx, runAs string, inner []string, awardRoot bool) ShellResult {
	r := ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
	if len(inner) == 0 {
		r.Handled = false
		return r
	}
	// a restricted NOPASSWD entry (awardRoot=false) may only run its exact whitelisted command;
	// it can never spawn a shell or switch user, so skip the escalation cases entirely.
	if awardRoot {
		switch inner[0] {
		case "su":
			tgt := "root"
			for _, a := range inner[1:] {
				if !strings.HasPrefix(a, "-") {
					tgt = a
					break
				}
			}
			r.User = tgt
			if acc := e.world.Unix[tgt]; acc != nil {
				r.Cwd = acc.Home
			}
			r.Flags = e.escalationFlags(c, tgt)
			return r
		case "-i", "-s", "bash", "sh", "/bin/bash", "/bin/sh", "/bin/zsh":
			r.User = runAs
			if runAs == "root" {
				r.Cwd = "/root"
			}
			r.Flags = e.escalationFlags(c, runAs)
			return r
		}
	}
	switch inner[0] {
	case "cat", "head", "tail", "ls", "ll":
		// run the read as the elevated user
		sub := &ShellCtx{User: runAs, Cwd: c.Cwd, Env: c.Env}
		cmd := simpleCmd{}
		for _, a := range inner {
			cmd.args = append(cmd.args, word{s: a, raw: a})
		}
		if inner[0] == "cat" || inner[0] == "head" || inner[0] == "tail" {
			if res, ok := e.doCat(sub, inner[0], cmd); ok {
				res.User, res.Cwd = c.User, c.Cwd
				if containsFlag(res.Flags, msCreds) {
					res.Flags = appendUniq(res.Flags, msCreds)
				}
				return res
			}
		} else if res, ok := e.doLs(sub, inner[0], cmd); ok {
			res.User, res.Cwd = c.User, c.Cwd
			return res
		}
	}
	// generic: let the LLM render output, but as the elevated user
	r.Handled = false
	r.Facts = e.factsAs(c, runAs)
	// A full sudoer running an arbitrary command as root effectively has root (they could run a
	// shell), so credit the milestone. A restricted NOPASSWD command (awardRoot=false) does not.
	if runAs == "root" && awardRoot {
		r.Flags = append(r.Flags, msRoot)
	}
	return r
}

func containsFlag(f []string, v string) bool {
	for _, x := range f {
		if x == v {
			return true
		}
	}
	return false
}

func (e *ShellEngine) factsAs(c *ShellCtx, user string) string {
	sub := *c
	sub.User = user
	return e.facts(&sub)
}

// sudoRights reports whether user may sudo at all, and whether without a password.
func (e *ShellEngine) sudoRights(user string) (allowed, nopasswd bool) {
	acc := e.world.Unix[user]
	if acc == nil {
		return false, false
	}
	if user == "root" {
		return true, true
	}
	for _, g := range acc.Groups {
		if g == "sudo" || g == "admin" {
			return true, false
		}
	}
	return false, false
}

// matchNopasswd handles deploy's NOPASSWD systemctl entries.
func (e *ShellEngine) matchNopasswd(user, full string) bool {
	if user != "deploy" {
		return false
	}
	full = strings.TrimSpace(full)
	return full == "/usr/bin/systemctl restart php7.4-fpm" || full == "systemctl restart php7.4-fpm" ||
		full == "/usr/bin/systemctl reload nginx" || full == "systemctl reload nginx"
}

func (e *ShellEngine) sudoList(user string, allowed, nopasswd bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Matching Defaults entries for %s on %s:\n", user, termHost)
	b.WriteString("    env_reset, mail_badpass,\n    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin\n\n")
	if user == "deploy" {
		fmt.Fprintf(&b, "User %s may run the following commands on %s:\n", user, termHost)
		b.WriteString("    (root) NOPASSWD: /usr/bin/systemctl restart php7.4-fpm, /usr/bin/systemctl reload nginx")
		return b.String()
	}
	if allowed {
		fmt.Fprintf(&b, "User %s may run the following commands on %s:\n", user, termHost)
		b.WriteString("    (ALL : ALL) ALL")
		return b.String()
	}
	return fmt.Sprintf("Sorry, user %s may not run sudo on %s.", user, termHost)
}

// ---------- mysql client ----------

func (e *ShellEngine) doMysql(ctx context.Context, c *ShellCtx, prog string, args []string) ShellResult {
	r := ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
	run := e.mysql.Invoke(ctx, c.SID, prog, args, c.User, "")
	return e.applyMysqlRun(c, run, r)
}

func (e *ShellEngine) applyMysqlRun(c *ShellCtx, run MySQLRun, r ShellResult) ShellResult {
	r.Output = run.Output
	if run.NeedPassword {
		r.Prompt = "Enter password: "
		r.Pending = &Pending{Kind: "mysql", Mysql: run.Pending}
	}
	if run.Interactive != nil {
		r.Interact = &Interactive{Mysql: run.Interactive}
		r.Prompt = "mysql> "
	}
	if run.Authed != "" {
		r.Flags = appendUniq(r.Flags, msDB)
	}
	return r
}

func (e *ShellEngine) continueMysql(ctx context.Context, c *ShellCtx, p *Pending, password string) ShellResult {
	r := ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
	run := e.mysql.Continue(ctx, c.SID, *p.Mysql, c.User, password)
	return e.applyMysqlRun(c, run, r)
}

// Continue dispatches a hidden password / monitor line to the right handler.
func (e *ShellEngine) Continue(ctx context.Context, c *ShellCtx, p *Pending, input string) ShellResult {
	switch p.Kind {
	case "su":
		return e.continueSu(c, p, input)
	case "sudo":
		return e.continueSudo(ctx, c, p, input)
	case "mysql", "mysqldump":
		return e.continueMysql(ctx, c, p, input)
	}
	return ShellResult{Cwd: c.Cwd, User: c.User, Handled: true}
}

// MergeMilestones adds new flags to a comma-separated milestone set, returns the set and whether it changed.
func MergeMilestones(existing string, add []string) (string, []string) {
	have := map[string]bool{}
	for _, m := range strings.Split(existing, ",") {
		if m = strings.TrimSpace(m); m != "" {
			have[m] = true
		}
	}
	var newly []string
	for _, m := range add {
		if !have[m] {
			have[m] = true
			newly = append(newly, m)
		}
	}
	var ordered []string
	for _, m := range milestoneOrder {
		if have[m] {
			ordered = append(ordered, m)
		}
	}
	return strings.Join(ordered, ","), newly
}
