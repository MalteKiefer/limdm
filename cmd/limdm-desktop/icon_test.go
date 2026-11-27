//go:build linux

package main

import (
	"bytes"
	"image/png"
	"testing"
)

// The three states must differ in shape, not only in color: compare where
// the badge is white (ring and glyph) between the icons.
func TestStatusIconsDifferInShape(t *testing.T) {
	mask := func(b []byte) string {
		img, err := png.Decode(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		var m []byte
		for y := 36; y < 64; y++ {
			for x := 36; x < 64; x++ {
				r, g, bl, _ := img.At(x, y).RGBA()
				if r > 0xe000 && g > 0xe000 && bl > 0xe000 {
					m = append(m, '#')
				} else {
					m = append(m, '.')
				}
			}
		}
		return string(m)
	}
	ok, warn, bad := mask(iconOK), mask(iconWarn), mask(iconBad)
	if ok == warn || ok == bad || warn == bad {
		t.Fatal("status icons only differ in color")
	}
}
