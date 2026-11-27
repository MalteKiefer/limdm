package server

import (
	"strings"
	"testing"
)

// fishRecording is a fish 3 session as the agent records it: title and
// working directory OSCs, bracketed paste, a coloured prompt with charset
// resets (ESC ( B), a right prompt, an autosuggestion that is redrawn on
// every key and erased on Enter, the missing newline marker and ls output.
var fishRecording = strings.Join([]string{
	"\x1b]0;~\x07\x1b]7;file://pc/home/malte\x1b\\\x1b[?2004h",
	// prompt, right prompt at column 70, back to the end of the prompt
	"\x1b[32mmalte\x1b(B\x1b[m@pc \x1b[32m~\x1b(B\x1b[m> \x1b[K\r\x1b[70C\x1b[90m12:00\x1b(B\x1b[m\r\x1b[12C",
	// typing "l": fish shows the suggestion "s -la" in grey and steps back
	"l\x1b[90ms -la\x1b(B\x1b[m\x1b[5D",
	// typing "s": redraw of the suggestion
	"s\x1b[90m -la\x1b(B\x1b[m\x1b[4D",
	// Enter: suggestion erased, newline, the command runs
	"\x1b[K\r\n\x1b[?2004l\x1b]0;ls ~\x07",
	"\x1b[01;34mDocuments\x1b[0m  a.txt  b.txt\r\n",
	// missing newline marker: ⏎ and spaces to the width, back, overwritten
	"\x1b[2m⏎\x1b(B\x1b[m" + strings.Repeat(" ", 79) + "\r \r",
	"\x1b[?2004h\x1b[32mmalte\x1b(B\x1b[m@pc \x1b[32m~\x1b(B\x1b[m> \x1b[K",
	"e\x1b[90mxit\x1b(B\x1b[m\x1b[3Dxit\x1b[K\r\n",
}, "")

const bashRecording = "\x1b]0;user@pc: ~\x07\x1b[?2004h\x1b[01;32muser@pc\x1b[00m:\x1b[01;34m~\x1b[00m$ ech\b\b\becho hi\r\n" +
	"\x1b[?2004lhi\r\n" +
	"progress  10%\rprogress  50%\rprogress 100%\r\n" +
	"\x1b[?2004huser@pc:~$ abc\x1b[2Dz\x1b[P\r\n" +
	"\x1b)0\x1b=user@pc:~$ exit\r\n\x1b>"

func TestTerminalText(t *testing.T) {
	for name, c := range map[string]struct{ in, want string }{
		"fish": {fishRecording, "malte@pc ~> ls\nDocuments  a.txt  b.txt\nmalte@pc ~> exit\n"},
		"bash": {bashRecording, "user@pc:~$ echo hi\nhi\nprogress 100%\nuser@pc:~$ az\nuser@pc:~$ exit\n"},
		"old":  {"\x1b[1;32muser@pc\x1b[0m:~$ ls\r\n\x1b]0;title\x07a\tb\x07\r\n", "user@pc:~$ ls\na\tb\n"},
		"cut":  {"text\x1b[1", "text"},
	} {
		if got := terminalText([]byte(c.in)); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", name, got, c.want)
		}
	}
}
