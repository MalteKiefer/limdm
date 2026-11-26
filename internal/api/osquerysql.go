package api

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ValidateOsquerySQL accepts a single read only SELECT (or WITH ... SELECT)
// statement that reads only tables of OsqueryTables or its own common table
// expressions. It runs on the server when an item is saved and on the agent
// before osqueryi sees the query.
func ValidateOsquerySQL(q string) error {
	if strings.TrimSpace(q) == "" || len(q) > 4096 {
		return errors.New("query: 1 to 4096 characters")
	}
	toks, err := sqlTokens(q)
	if err != nil {
		return err
	}
	for len(toks) > 0 && toks[len(toks)-1].is(";") {
		toks = toks[:len(toks)-1]
	}
	if len(toks) == 0 || toks[0].kind != tokWord || (toks[0].text != "select" && toks[0].text != "with") {
		return errors.New("query: must start with SELECT or WITH")
	}
	for i, t := range toks {
		named := t.kind == tokWord || t.kind == tokIdent
		switch {
		case t.is(";"):
			return errors.New("query: exactly one statement")
		case t.kind == tokWord && t.text == "replace" && i+1 < len(toks) && toks[i+1].is("("):
			// the string function replace(), not the statement
		case t.kind == tokWord && sqlForbidden[t.text], named && sqlForbiddenNames[t.text]:
			return fmt.Errorf("query: %q is not allowed (read only queries)", t.text)
		}
	}
	return sqlTables(toks)
}

type sqlTok struct {
	kind int
	text string // lower case for words and quoted names
}

const (
	tokWord  = iota // bare keyword or name
	tokIdent        // quoted name: "x", [x] or `x`
	tokStr          // 'string'
	tokNum
	tokPunct
)

func (t sqlTok) is(p string) bool { return t.kind == tokPunct && t.text == p }

// sqlTokens splits a query the way SQLite does. Outside string literals only
// ASCII is accepted, so look alike letters cannot hide a name; comments and
// control characters are refused.
func sqlTokens(q string) ([]sqlTok, error) {
	var out []sqlTok
	ascii := errors.New("query: only ASCII is allowed outside string literals")
	for i := 0; i < len(q); {
		c := q[i]
		switch {
		case c == ' ' || c == '\n' || c == '\t' || c == '\r':
			i++
		case c < 0x20 || c == 0x7f:
			return nil, errors.New("query: control characters are not allowed")
		case c >= 0x80:
			return nil, ascii
		case strings.HasPrefix(q[i:], "--"), strings.HasPrefix(q[i:], "/*"):
			return nil, errors.New("query: comments are not allowed")
		case c == '\'' || c == '"' || c == '`' || c == '[':
			closer := map[byte]byte{'\'': '\'', '"': '"', '`': '`', '[': ']'}[c]
			var b strings.Builder
			j := i + 1
			for ; j < len(q); j++ {
				if q[j] == closer {
					if closer != ']' && j+1 < len(q) && q[j+1] == closer { // doubled quote escapes itself
						b.WriteByte(closer)
						j++
						continue
					}
					break
				}
				b.WriteByte(q[j])
			}
			if j >= len(q) {
				return nil, errors.New("query: unterminated quote")
			}
			s := b.String()
			if c == '\'' {
				out = append(out, sqlTok{tokStr, s})
			} else {
				if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r >= 0x7f }) {
					return nil, ascii
				}
				out = append(out, sqlTok{tokIdent, strings.ToLower(s)})
			}
			i = j + 1
		case c == '_' || c == '$' || isAlnum(c):
			j := i
			for j < len(q) && (q[j] == '_' || q[j] == '$' || isAlnum(q[j])) {
				j++
			}
			kind := tokWord
			if c >= '0' && c <= '9' {
				kind = tokNum
			}
			out = append(out, sqlTok{kind, strings.ToLower(q[i:j])})
			i = j
		default:
			out = append(out, sqlTok{tokPunct, string(c)})
			i++
		}
	}
	return out, nil
}

func isAlnum(c byte) bool { return (c|0x20 >= 'a' && c|0x20 <= 'z') || (c >= '0' && c <= '9') }

// sqlTables finds every table reference (after FROM, JOIN, a comma in a FROM
// clause and IN) and accepts only OsqueryTables and the common table
// expressions of a leading WITH, referenced after their declaration.
func sqlTables(toks []sqlTok) error {
	isName := func(i int) bool { return i < len(toks) && (toks[i].kind == tokWord || toks[i].kind == tokIdent) }
	ctes := map[string]int{} // name -> token index of its declaration
	if toks[0].text == "with" {
		i := 1
		if isName(i) && toks[i].text == "recursive" {
			i++
		}
		for isName(i) {
			ctes[toks[i].text] = i
			if i++; i < len(toks) && toks[i].is("(") {
				i = sqlClose(toks, i)
			}
			if !isName(i) || toks[i].text != "as" {
				break
			}
			for i++; isName(i) && (toks[i].text == "not" || toks[i].text == "materialized"); i++ {
			}
			if i >= len(toks) || !toks[i].is("(") {
				break
			}
			if i = sqlClose(toks, i); i >= len(toks) || !toks[i].is(",") {
				break
			}
			i++
		}
	}
	inFrom := map[int]bool{} // a FROM clause is open at this parenthesis depth
	depth, table := 0, false
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if table {
			table = false
			switch {
			case t.is("("):
				// a parenthesised join holds table names, a subquery has its own FROM
				depth++
				next := ""
				if i+1 < len(toks) {
					next = toks[i+1].text
				}
				inFrom[depth] = next != "select" && next != "with" && next != "values"
				table = inFrom[depth]
			case isName(i):
				name, at := t.text, i
				if i+2 < len(toks) && toks[i+1].is(".") && isName(i+2) { // schema.table
					i += 2
					name = toks[i].text
				}
				if d, ok := ctes[name]; ok && at == i && at > d {
					continue
				}
				if !slices.Contains(OsqueryTables, name) {
					return fmt.Errorf("query: table %q is not allowed (allowed: %s)", name, strings.Join(OsqueryTables, ", "))
				}
			default:
				return errors.New("query: table name expected")
			}
			continue
		}
		switch {
		case t.is("("):
			depth++
			inFrom[depth] = false
		case t.is(")"):
			inFrom[depth] = false
			depth--
		case t.is(","):
			table = inFrom[depth]
		case t.kind != tokWord:
		case t.text == "from":
			inFrom[depth], table = true, true
		case t.text == "join":
			table = true
		case t.text == "in":
			table = isName(i + 1) // x IN table
		case slices.Contains([]string{"where", "group", "order", "limit", "having", "window", "union", "except", "intersect", "select", "values"}, t.text):
			inFrom[depth] = false
		}
	}
	if table {
		return errors.New("query: table name expected")
	}
	return nil
}

// sqlClose returns the index after the parenthesis that closes toks[i].
func sqlClose(toks []sqlTok, i int) int {
	for n := 0; i < len(toks); i++ {
		switch {
		case toks[i].is("("):
			n++
		case toks[i].is(")"):
			if n--; n == 0 {
				return i + 1
			}
		}
	}
	return i
}
