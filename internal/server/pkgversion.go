package server

import (
	"strings"
)

// Version comparison of pacman (Arch) and apk (Alpine), as their package
// managers do it; Debian is in debversion.go.

// versionCompare picks the comparison rules of a distribution.
func versionCompare(distro string) func(a, b string) int {
	switch distro {
	case "arch":
		return pacCompare
	case "alpine":
		return apkCompare
	}
	return debCompare
}

// pacCompare is alpm_pkg_vercmp: [epoch:]pkgver[-pkgrel]. The epoch (0
// when missing) and pkgver compare with rpmvercmp; pkgrel only when both
// versions have one.
func pacCompare(a, b string) int {
	if a == b {
		return 0
	}
	ea, va, ra := splitPacVersion(a)
	eb, vb, rb := splitPacVersion(b)
	if c := rpmvercmp(ea, eb); c != 0 {
		return c
	}
	if c := rpmvercmp(va, vb); c != 0 || ra == "" || rb == "" {
		return c
	}
	return rpmvercmp(ra, rb)
}

func splitPacVersion(v string) (epoch, ver, rel string) {
	epoch = "0"
	i := 0
	for i < len(v) && isDigit(v[i]) {
		i++
	}
	if i < len(v) && v[i] == ':' {
		if i > 0 {
			epoch = v[:i]
		}
		v = v[i+1:]
	}
	if j := strings.LastIndexByte(v, '-'); j >= 0 {
		return epoch, v[:j], v[j+1:]
	}
	return epoch, v, ""
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isAlnum(c byte) bool { return isAlpha(c) || isDigit(c) }

// at is the byte at i of s, 0 past the end (the C string terminator).
func at(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// rpmvercmp is libalpm's segment comparison: alphanumeric segments split
// by separators; a longer separator wins, numeric segments beat alpha
// ones and compare as numbers, and a remaining alpha segment never beats
// the end of the other version.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	one, two := 0, 0
	p1, p2 := 0, 0
	for one < len(a) && two < len(b) {
		for one < len(a) && !isAlnum(a[one]) {
			one++
		}
		for two < len(b) && !isAlnum(b[two]) {
			two++
		}
		if one >= len(a) || two >= len(b) {
			break
		}
		if one-p1 != two-p2 { // separator lengths
			if one-p1 < two-p2 {
				return -1
			}
			return 1
		}
		p1, p2 = one, two
		isnum := isDigit(a[p1])
		class := isAlpha
		if isnum {
			class = isDigit
		}
		for p1 < len(a) && class(a[p1]) {
			p1++
		}
		for p2 < len(b) && class(b[p2]) {
			p2++
		}
		if two == p2 { // different segment types: numeric is newer
			if isnum {
				return 1
			}
			return -1
		}
		sa, sb := a[one:p1], b[two:p2]
		if isnum {
			sa, sb = strings.TrimLeft(sa, "0"), strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				return sign(len(sa) - len(sb))
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
		one, two = p1, p2
	}
	if one >= len(a) && two >= len(b) {
		return 0
	}
	if one >= len(a) && !isAlpha(at(b, two)) || isAlpha(at(a, one)) {
		return -1
	}
	return 1
}

// apk version tokens, in apk-tools' order (version.c).
const (
	apkDigitOrZero = iota
	apkDigit
	apkLetter
	apkSuffix
	apkSuffixNo
	apkRevisionNo
	apkEnd
	apkInvalid = -1
)

var (
	apkPreSuffixes  = []string{"alpha", "beta", "pre", "rc"}
	apkPostSuffixes = []string{"cvs", "svn", "git", "hg", "p"}
)

// apkNextToken reads the separator after a token and returns the next
// token type.
func apkNextToken(typ int, s string) (int, string) {
	n := apkInvalid
	switch {
	case s == "":
		n = apkEnd
	case (typ == apkDigit || typ == apkDigitOrZero) && s[0] >= 'a' && s[0] <= 'z':
		n = apkLetter
	case typ == apkLetter && isDigit(s[0]):
		n = apkDigit
	case typ == apkSuffix && isDigit(s[0]):
		n = apkSuffixNo
	default:
		switch s[0] {
		case '.':
			n = apkDigitOrZero
		case '_':
			n = apkSuffix
		case '-':
			if len(s) > 1 && s[1] == 'r' {
				n = apkRevisionNo
				s = s[1:]
			}
		}
		s = s[1:]
	}
	// a token may only go back to an earlier type in these steps (1.2, _rc1_p, 1a1)
	allowed := n == apkDigitOrZero && typ == apkDigit || n == apkSuffix && typ == apkSuffixNo || n == apkDigit && typ == apkLetter
	if n < typ && n != apkInvalid && !allowed {
		n = apkInvalid
	}
	return n, s
}

// apkGetToken reads one token of type typ: its value, the next type and
// the rest.
func apkGetToken(typ int, s string) (int, int, string) {
	if s == "" {
		return 0, apkEnd, s
	}
	v, i, nt := 0, 0, apkInvalid
	switch typ {
	case apkDigitOrZero, apkDigit, apkSuffixNo, apkRevisionNo:
		if typ == apkDigitOrZero && s[0] == '0' { // leading zeros after a dot: a fraction (1.01 < 1.1)
			for i < len(s) && s[i] == '0' {
				i++
			}
			v = -i
			if i < len(s) && isDigit(s[i]) {
				nt = apkDigit // the digits after the zeros follow as their own token
			}
			// a part of zeros only ("1.0_rc") goes on with its separator,
			// so the pre-release suffix still sorts before "1.0"
			break
		}
		for i < len(s) && isDigit(s[i]) {
			v = v*10 + int(s[i]-'0')
			i++
		}
	case apkLetter:
		v, i = int(s[0]), 1
	case apkSuffix:
		found := false
		for k, suf := range apkPreSuffixes {
			if strings.HasPrefix(s, suf) {
				v, i, found = k-len(apkPreSuffixes), len(suf), true
				break
			}
		}
		for k, suf := range apkPostSuffixes {
			if !found && strings.HasPrefix(s, suf) {
				v, i, found = k, len(suf), true
			}
		}
		if !found {
			return -1, apkInvalid, s
		}
	default:
		return -1, apkInvalid, s
	}
	s = s[i:]
	switch {
	case s == "":
		return v, apkEnd, s
	case nt != apkInvalid:
		return v, nt, s
	}
	nt, s = apkNextToken(typ, s)
	return v, nt, s
}

// apkCompare is apk-tools' version comparison: digits, an optional
// letter, suffixes (_alpha, _beta, _pre, _rc before the release; _cvs,
// _svn, _git, _hg, _p after it) with numbers, and -rN.
func apkCompare(a, b string) int {
	at, bt, av, bv := apkDigit, apkDigit, 0, 0
	for at == bt && at != apkEnd && at != apkInvalid && av == bv {
		av, at, a = apkGetToken(at, a)
		bv, bt, b = apkGetToken(bt, b)
	}
	switch {
	case av < bv:
		return -1
	case av > bv:
		return 1
	case at == bt:
		return 0
	}
	// equal so far: the longer version is newer, unless it goes on with
	// a pre-release suffix
	if at == apkSuffix {
		if v, _, _ := apkGetToken(at, a); v < 0 {
			return -1
		}
	}
	if bt == apkSuffix {
		if v, _, _ := apkGetToken(bt, b); v < 0 {
			return 1
		}
	}
	switch {
	case at > bt:
		return -1
	case bt > at:
		return 1
	}
	return 0
}
