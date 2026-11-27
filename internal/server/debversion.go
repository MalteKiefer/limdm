package server

import (
	"strconv"
	"strings"
)

// debCompare compares two Debian package versions ([epoch:]upstream[-revision])
// as dpkg does (dpkg's verrevcmp): -1, 0 or 1. The epoch compares as a
// number; upstream and revision alternate non digit parts, where ~ sorts
// before everything (even the end), letters before other characters, and
// digit parts compared as numbers. A missing revision equals "0".
func debCompare(a, b string) int {
	ea, ua, ra := splitDebVersion(a)
	eb, ub, rb := splitDebVersion(b)
	if ea != eb {
		return sign(ea - eb)
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

func splitDebVersion(v string) (epoch int, upstream, revision string) {
	v = strings.TrimSpace(v)
	if e, rest, ok := strings.Cut(v, ":"); ok {
		if n, err := strconv.Atoi(e); err == nil {
			epoch, v = n, rest
		}
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// debOrder is the weight of the character at i of s (0 past the end).
func debOrder(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	switch c := s[i]; {
	case c == '~':
		return -1
	case isDigit(c):
		return 0
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isDigit(a[i]) || j < len(b) && !isDigit(b[j]) {
			if ac, bc := debOrder(a, i), debOrder(b, j); ac != bc {
				return sign(ac - bc)
			}
			i, j = i+1, j+1
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		diff := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if diff == 0 {
				diff = int(a[i]) - int(b[j])
			}
			i, j = i+1, j+1
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if diff != 0 {
			return sign(diff)
		}
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
