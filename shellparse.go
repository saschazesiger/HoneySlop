package main

import (
	"errors"
	"strings"
)

// A small bash-like parser: enough to decide which command lines can be executed deterministically
// (everything else goes to the LLM together with the security facts).

type word struct {
	s    string // value after quote removal
	dyn  bool   // contains $..., $(...), `...` that we don't expand
	glob bool   // contains unquoted * ? [
	vars bool   // contains simple $VAR / ${VAR} references (expandable)
	raw  string
}

type redir struct {
	op     string // >, >>, <, 2>, 2>>, &>, 2>&1, >&2
	target string
}

type simpleCmd struct {
	args   []word
	redirs []redir
}

func (c simpleCmd) name() string {
	if len(c.args) == 0 {
		return ""
	}
	return c.args[0].s
}

func (c simpleCmd) argv() []string {
	out := make([]string, len(c.args))
	for i, a := range c.args {
		out[i] = a.s
	}
	return out
}

type pipeline struct{ cmds []simpleCmd }

// cmdList is pipelines joined by ; && ||
type cmdList struct {
	pipes []pipeline
	ops   []string // ops[i] joins pipes[i] and pipes[i+1]
	bg    bool     // contains & (background)
}

var errUnsupported = errors.New("unsupported shell syntax")

type ltok struct {
	w  word
	op string // non-empty for operators
}

func lexShell(line string) ([]ltok, error) {
	var out []ltok
	i, n := 0, len(line)
	for i < n {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			i++
			continue
		case c == '#':
			return out, nil // comment until end of line
		case c == '|' || c == '&' || c == ';' || c == '>' || c == '<' || c == '(' || c == ')':
			two := ""
			if i+1 < n {
				two = line[i : i+2]
			}
			switch {
			case two == "||" || two == "&&" || two == ">>" || two == "&>" || two == ">&" || two == ";;" || two == "<<":
				if two == ">&" || two == "<<" || two == ";;" {
					return nil, errUnsupported
				}
				out = append(out, ltok{op: two})
				i += 2
			case c == '(' || c == ')':
				return nil, errUnsupported
			default:
				out = append(out, ltok{op: string(c)})
				i++
			}
			continue
		}
		// word (possibly with fd prefix for redirections like 2> / 2>&1)
		if (c == '1' || c == '2') && i+1 < n && line[i+1] == '>' && (i == 0 || line[i-1] == ' ') {
			fd := string(c)
			if i+3 < n && line[i+2] == '&' && (line[i+3] == '1' || line[i+3] == '2') {
				out = append(out, ltok{op: fd + ">&" + string(line[i+3])})
				i += 4
				continue
			}
			if i+2 < n && line[i+2] == '>' {
				out = append(out, ltok{op: fd + ">>"})
				i += 3
				continue
			}
			out = append(out, ltok{op: fd + ">"})
			i += 2
			continue
		}
		var w word
		var b strings.Builder
		start := i
	loop:
		for i < n {
			c := line[i]
			switch c {
			case ' ', '\t', '|', '&', ';', '>', '<', '(', ')':
				break loop
			case '\\':
				if i+1 < n {
					b.WriteByte(line[i+1])
					i += 2
					continue
				}
				i++
			case '\'':
				j := strings.IndexByte(line[i+1:], '\'')
				if j < 0 {
					return nil, errUnsupported
				}
				b.WriteString(line[i+1 : i+1+j])
				i += j + 2
			case '"':
				i++
				for i < n && line[i] != '"' {
					if line[i] == '\\' && i+1 < n && strings.IndexByte("\"\\$`", line[i+1]) >= 0 {
						b.WriteByte(line[i+1])
						i += 2
						continue
					}
					if line[i] == '`' || (line[i] == '$' && i+1 < n && line[i+1] == '(') {
						w.dyn = true
					} else if line[i] == '$' {
						w.vars = true
					}
					b.WriteByte(line[i])
					i++
				}
				if i >= n {
					return nil, errUnsupported
				}
				i++
			case '`':
				w.dyn = true
				b.WriteByte(c)
				i++
			case '$':
				if i+1 < n && (line[i+1] == '(' || line[i+1] == '[') {
					return nil, errUnsupported
				}
				w.vars = true
				b.WriteByte(c)
				i++
			case '*', '?', '[':
				w.glob = true
				b.WriteByte(c)
				i++
			default:
				b.WriteByte(c)
				i++
			}
		}
		w.s, w.raw = b.String(), line[start:i]
		out = append(out, ltok{w: w})
	}
	return out, nil
}

// parseShell parses a command line into pipelines. Heredocs, subshells, functions etc. return errUnsupported.
func parseShell(line string) (cmdList, error) {
	toks, err := lexShell(line)
	if err != nil {
		return cmdList{}, err
	}
	var l cmdList
	var cur pipeline
	var cmd simpleCmd
	flushCmd := func() error {
		if len(cmd.args) == 0 {
			if len(cmd.redirs) > 0 {
				return errUnsupported
			}
			return errors.New("empty command")
		}
		cur.cmds = append(cur.cmds, cmd)
		cmd = simpleCmd{}
		return nil
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch t.op {
		case "":
			cmd.args = append(cmd.args, t.w)
		case "|":
			if err := flushCmd(); err != nil {
				return l, err
			}
		case ";", "&&", "||", "&":
			if t.op == "&" {
				l.bg = true
			}
			if len(cmd.args) == 0 && len(cur.cmds) == 0 && (t.op == ";" || t.op == "&") && i == len(toks)-1 {
				continue
			}
			if err := flushCmd(); err != nil {
				return l, err
			}
			l.pipes = append(l.pipes, cur)
			cur = pipeline{}
			if i < len(toks)-1 {
				op := t.op
				if op == "&" {
					op = ";"
				}
				l.ops = append(l.ops, op)
			}
		case "2>&1", "1>&2", "2>&2", "1>&1":
			cmd.redirs = append(cmd.redirs, redir{op: t.op})
		default: // >, >>, <, &>, 2>, 2>>, 1>
			if i+1 >= len(toks) || toks[i+1].op != "" {
				return l, errors.New("syntax error near unexpected token `newline'")
			}
			op := strings.TrimPrefix(t.op, "1")
			cmd.redirs = append(cmd.redirs, redir{op: op, target: toks[i+1].w.s})
			if toks[i+1].w.dyn || toks[i+1].w.vars || toks[i+1].w.glob {
				return l, errUnsupported
			}
			i++
		}
	}
	if len(cmd.args) > 0 || len(cmd.redirs) > 0 {
		if err := flushCmd(); err != nil {
			return l, err
		}
	}
	if len(cur.cmds) > 0 {
		l.pipes = append(l.pipes, cur)
	}
	if len(l.ops) >= len(l.pipes) && len(l.ops) > 0 {
		l.ops = l.ops[:len(l.pipes)-1]
	}
	return l, nil
}

// allCmds iterates all simple commands of a list.
func (l cmdList) allCmds() []simpleCmd {
	var out []simpleCmd
	for _, p := range l.pipes {
		out = append(out, p.cmds...)
	}
	return out
}
