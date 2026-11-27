package server

import (
	"strconv"
	"strings"
)

// terminalText turns a recorded terminal stream into the text that was
// visible, for the transcript view, search and exports. Every escape
// sequence is removed (CSI with private modes, OSC ended by BEL or ST, DCS,
// SOS, PM and APC strings, nF sequences such as the charset designation
// ESC ( B, single character escapes). Each line is a buffer with a cursor:
// carriage return goes to the line start and later text overwrites, BS
// moves back, CSI K/P/X/@ erase, delete and insert, CSI C/D/G move the
// cursor. So shell redraws (fish autosuggestions, the missing newline
// marker, progress bars) collapse to what the screen showed.
//
// ponytail: one line at a time; cursor up/down and absolute positioning
// (full screen programs like vim or top) are ignored, and lines the
// terminal wrapped softly are not joined because the width is unknown.
func terminalText(raw []byte) string {
	rs := []rune(strings.ToValidUTF8(string(raw), "�"))
	var out strings.Builder
	var line []rune
	col := 0
	put := func(r rune) {
		for len(line) < col {
			line = append(line, ' ')
		}
		if col < len(line) {
			line[col] = r
		} else {
			line = append(line, r)
		}
		col++
	}
	flush := func() {
		out.WriteString(strings.TrimRight(string(line), " "))
		out.WriteByte('\n')
		line, col = line[:0], 0
	}
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == 0x1b:
			i = skipEscape(rs, i, func(final rune, params string) {
				n, _ := strconv.Atoi(strings.TrimLeft(params, "?>="))
				switch final {
				case 'K': // erase in line: 0 to the end, 1 to the start, 2 all
					switch n {
					case 0:
						if col < len(line) {
							line = line[:col]
						}
					case 1:
						for j := 0; j <= col && j < len(line); j++ {
							line[j] = ' '
						}
					case 2:
						line = line[:0]
					}
				case 'C':
					col += max(n, 1)
				case 'D':
					col = max(col-max(n, 1), 0)
				case 'G':
					col = max(n, 1) - 1
				case 'P': // delete characters at the cursor
					if col < len(line) {
						line = append(line[:col], line[min(col+max(n, 1), len(line)):]...)
					}
				case 'X': // erase characters at the cursor
					for j := col; j < col+max(n, 1) && j < len(line); j++ {
						line[j] = ' '
					}
				case '@': // insert blanks at the cursor
					if col < len(line) {
						line = append(line[:col], append([]rune(strings.Repeat(" ", max(n, 1))), line[col:]...)...)
					}
				}
			})
		case r == '\n':
			flush()
		case r == '\r':
			col = 0
		case r == '\b':
			col = max(col-1, 0)
		case r == '\t' || r >= 0x20 && r != 0x7f && (r < 0x80 || r > 0x9f):
			put(r)
		}
	}
	out.WriteString(strings.TrimRight(string(line), " "))
	return out.String()
}

// skipEscape returns the index of the last rune of the escape sequence that
// starts at rs[i] (ESC); for CSI it calls csi with the final byte and the
// parameter bytes.
func skipEscape(rs []rune, i int, csi func(final rune, params string)) int {
	if i+1 >= len(rs) {
		return i
	}
	j := i + 1
	switch c := rs[j]; {
	case c == '[': // CSI: parameters 0x30-0x3f, intermediates 0x20-0x2f, final 0x40-0x7e
		start := j + 1
		for j++; j < len(rs) && rs[j] >= 0x30 && rs[j] <= 0x3f; j++ {
		}
		params := string(rs[start:j])
		for ; j < len(rs) && rs[j] >= 0x20 && rs[j] <= 0x2f; j++ {
		}
		if j < len(rs) && rs[j] >= 0x40 && rs[j] <= 0x7e {
			csi(rs[j], params)
			return j
		}
		return min(j, len(rs)-1)
	case c == ']' || c == 'P' || c == 'X' || c == '^' || c == '_': // strings up to BEL (OSC) or ST
		for j++; j < len(rs); j++ {
			if rs[j] == 0x07 && c == ']' {
				return j
			}
			if rs[j] == 0x1b && j+1 < len(rs) && rs[j+1] == '\\' {
				return j + 1
			}
		}
		return len(rs) - 1
	case c >= 0x20 && c <= 0x2f: // nF: ESC ( B, ESC ) 0, ESC # 8 ...
		for ; j < len(rs) && rs[j] >= 0x20 && rs[j] <= 0x2f; j++ {
		}
		return min(j, len(rs)-1)
	default: // ESC 7, ESC =, ESC M ...
		return j
	}
}
