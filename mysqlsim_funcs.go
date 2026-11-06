package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

// Helpers implementing MySQL builtins that SQLite lacks. Arguments arrive as
// driver.Value (int64, float64, string, []byte, nil). MySQL concatenation and
// most string functions return NULL if any argument is NULL.

func argStr(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", false
	case string:
		return t, true
	case []byte:
		return string(t), true
	case int64:
		return fmt.Sprintf("%d", t), true
	case float64:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", t), "0"), "."), true
	case bool:
		if t {
			return "1", true
		}
		return "0", true
	default:
		return fmt.Sprintf("%v", t), true
	}
}

func fnConcat(args []any) (any, error) {
	var b strings.Builder
	for _, a := range args {
		s, ok := argStr(a)
		if !ok {
			return nil, nil // NULL propagates
		}
		b.WriteString(s)
	}
	return b.String(), nil
}

func fnConcatWS(args []any) (any, error) {
	if len(args) == 0 {
		return nil, nil
	}
	sep, ok := argStr(args[0])
	if !ok {
		return nil, nil
	}
	var parts []string
	for _, a := range args[1:] {
		if s, ok := argStr(a); ok { // CONCAT_WS skips NULL args
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, sep), nil
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case int64:
		return t != 0
	case float64:
		return t != 0
	case string:
		return t != "" && t != "0"
	case []byte:
		s := string(t)
		return s != "" && s != "0"
	case bool:
		return t
	}
	return false
}

func fnIf(args []any) (any, error) {
	if truthy(args[0]) {
		return args[1], nil
	}
	return args[2], nil
}

func fnLeft(args []any) (any, error) {
	s, ok := argStr(args[0])
	if !ok {
		return nil, nil
	}
	n := toInt(args[1])
	if n < 0 {
		n = 0
	}
	r := []rune(s)
	if n > len(r) {
		n = len(r)
	}
	return string(r[:n]), nil
}

func fnRight(args []any) (any, error) {
	s, ok := argStr(args[0])
	if !ok {
		return nil, nil
	}
	n := toInt(args[1])
	if n < 0 {
		n = 0
	}
	r := []rune(s)
	if n > len(r) {
		n = len(r)
	}
	return string(r[len(r)-n:]), nil
}

// fnSubstr3 implements MID(str, pos, len) with 1-based pos (MySQL semantics).
func fnSubstr3(args []any) (any, error) {
	s, ok := argStr(args[0])
	if !ok {
		return nil, nil
	}
	pos := toInt(args[1])
	ln := toInt(args[2])
	r := []rune(s)
	if pos < 0 {
		pos = len(r) + pos + 1
	}
	if pos < 1 {
		pos = 1
	}
	start := pos - 1
	if start >= len(r) {
		return "", nil
	}
	end := start + ln
	if ln < 0 || end > len(r) {
		end = len(r)
	}
	if end < start {
		end = start
	}
	return string(r[start:end]), nil
}

func fnMD5(args []any) (any, error) {
	s, ok := argStr(args[0])
	if !ok {
		return nil, nil
	}
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:]), nil
}

func fnSHA1(args []any) (any, error) {
	s, ok := argStr(args[0])
	if !ok {
		return nil, nil
	}
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:]), nil
}

func toInt(v any) int {
	switch t := v.(type) {
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		var n int
		fmt.Sscanf(t, "%d", &n)
		return n
	case []byte:
		var n int
		fmt.Sscanf(string(t), "%d", &n)
		return n
	}
	return 0
}
