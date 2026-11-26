package server

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// friendlyMsg is an error message for the console: a translated text and,
// when the text had to be derived from a technical message, that message.
type friendlyMsg struct {
	Text, Detail string
}

// goTypeNames turns the Go types of a JSON decoder error into words.
var goTypeNames = map[string]string{"string": "text", "bool": "true or false", "int": "a number", "int64": "a number",
	"uint": "a number", "uint64": "a number", "float64": "a number", "map": "an object"}

// errorRules map frequent technical messages (JSON decoder, range checks of
// the declaration validation) to translatable texts; %s takes the groups.
var errorRules = []struct {
	re   *regexp.Regexp
	text string
}{
	{regexp.MustCompile(`json: unknown field "([^"]+)"`), "Unknown field %s: check the spelling against the field reference."},
	{regexp.MustCompile(`json: cannot unmarshal \w+ into Go (?:struct field \S*?\.|value of type )([\w.\[\]]+) of type (\S+)`), "The field %s has the wrong type: expected %s."},
	{regexp.MustCompile(`invalid character|unexpected end of JSON input|^trailing data$`), "The settings are not valid JSON. Use Format to find the spot."},
	{regexp.MustCompile(`^([\w ]+?) must be (-?\d+)\s*\.\.\s*(-?\d+)`), "%s must be between %s and %s."},
	{regexp.MustCompile(`^([\w ]+?) must be (-?\d+) \(off\) up to (\d+)`), "%s must be between %s and %s."},
	{regexp.MustCompile(`^([\w ]+?):? (\d+) to (\d+) characters`), "%s must have %s to %s characters."},
	{regexp.MustCompile(`^item is used by blueprints: (.+)$`), "The library item is still used by these blueprints: %s. Remove it there first."},
}

// friendlyError translates msg for the console. A message with a catalog
// entry is translated as is; a known technical pattern gets a readable text
// and keeps the original as detail; anything else stays as it is. Joined
// errors (one per line) are handled line by line.
func friendlyError(lang, msg string) friendlyMsg {
	msg = strings.TrimSpace(msg)
	if t := translate(lang, msg); t != msg || !strings.Contains(msg, "\n") {
		return friendlyLine(lang, msg)
	}
	var texts []string
	for _, l := range strings.Split(msg, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			texts = append(texts, friendlyLine(lang, l).Text)
		}
	}
	return friendlyMsg{Text: strings.Join(texts, " "), Detail: msg}
}

func friendlyLine(lang, msg string) friendlyMsg {
	if t := translate(lang, msg); t != msg {
		return friendlyMsg{Text: t}
	}
	for _, rule := range errorRules {
		m := rule.re.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		args := make([]any, 0, len(m)-1)
		for _, g := range m[1:] {
			if w, ok := goTypeNames[strings.TrimPrefix(g, "*")]; ok {
				g = translate(lang, w)
			} else if strings.HasPrefix(g, "[]") {
				g = translate(lang, "a list")
			}
			args = append(args, g)
		}
		return friendlyMsg{Text: fmt.Sprintf(translate(lang, rule.text), args...), Detail: msg}
	}
	return friendlyMsg{Text: msg}
}

// errorTitles head the error page per status code.
var errorTitles = map[int]string{
	http.StatusBadRequest: "The input was not accepted", http.StatusForbidden: "Not allowed",
	http.StatusNotFound: "Not found", http.StatusConflict: "Not possible right now",
	http.StatusTooManyRequests: "Too many attempts",
}

// errorPage answers a console request with the message inside the layout
// and a link back to the page the user came from (same host only).
func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, sess session, code int, msg string) {
	if s.rt.Load() == nil { // a bare Server (handler tests) has no settings to render with
		http.Error(w, msg, code)
		return
	}
	back := "/"
	if u, err := url.Parse(r.Referer()); err == nil && u.Host == r.Host && strings.HasPrefix(u.Path, "/") && !strings.HasPrefix(u.Path, "//") {
		back = u.RequestURI()
	}
	title, ok := errorTitles[code]
	if !ok {
		title = "Something went wrong"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	s.render(w, r, sess, "error", map[string]any{"Title": title, "Msg": msg, "Back": back})
}

// notFound is errorPage for a missing object.
func (s *Server) notFound(w http.ResponseWriter, r *http.Request, sess session) {
	s.errorPage(w, r, sess, http.StatusNotFound, "This page or object does not exist (any more).")
}
