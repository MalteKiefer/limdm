package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Tray icon states. The state shows in the badge's shape (check mark,
// exclamation mark, cross) and in the tooltip, never in its color alone.
const (
	stateOK = iota
	stateWarn
	stateBad
)

var (
	iconOK   = statusIcon(stateOK)
	iconWarn = statusIcon(stateWarn)
	iconBad  = statusIcon(stateBad)
)

// statusIcon draws the symbolic LiMDM logo (shield outline with a prompt, see
// packaging/artwork/limdm-symbolic.svg) with a status badge in the lower
// right corner. Tray pixmaps cannot follow the panel's colors, so the shield
// is dark on a white fill: it reads on light and dark panels alike. Drawn in
// code: the tray needs pixels and the binary has no SVG renderer.
func statusIcon(state int) []byte {
	const n, ss = 64, 4 // pixels, samples per axis
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					// coordinates of the 128 unit logo
					c := iconSample((float64(x)+(float64(sx)+0.5)/ss)*2, (float64(y)+(float64(sy)+0.5)/ss)*2, state)
					af := float64(c.A) / 255
					r, g, b, a = r+float64(c.R)*af, g+float64(c.G)*af, b+float64(c.B)*af, a+af
				}
			}
			if a == 0 {
				continue
			}
			img.SetNRGBA(x, y, color.NRGBA{uint8(r / a), uint8(g / a), uint8(b / a), uint8(a / ss / ss * 255)})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img) // in-memory encoding of a valid image cannot fail
	return buf.Bytes()
}

// shieldHalf is the half width of the shield at height py, 0 outside.
func shieldHalf(py float64) float64 {
	switch {
	case py >= 8 && py < 22:
		return 44 * (0.6 + 0.4*(py-8)/14)
	case py >= 22 && py < 58:
		return 44
	case py >= 58 && py <= 120:
		k := (py - 58) / 62
		return 44 * math.Sqrt(1-k*k)
	}
	return 0
}

func iconSample(px, py float64, state int) color.RGBA {
	white := color.RGBA{0xff, 0xff, 0xff, 0xff}
	dark := color.RGBA{0x24, 0x1f, 0x31, 0xff}
	seg := func(ax, ay, bx, by float64) float64 { // distance to a segment
		dx, dy := bx-ax, by-ay
		t := math.Max(0, math.Min(1, ((px-ax)*dx+(py-ay)*dy)/(dx*dx+dy*dy)))
		return math.Hypot(px-ax-t*dx, py-ay-t*dy)
	}

	// badge: a disc with a white ring, its glyph cut out in white
	if d := math.Hypot(px-100, py-100); d <= 28 {
		if d > 23 {
			return white
		}
		const w = 3.2
		var glyph bool
		switch state {
		case stateOK:
			glyph = seg(89, 101, 97, 109) < w || seg(97, 109, 112, 91) < w
		case stateWarn:
			glyph = seg(100, 86, 100, 104) < w || math.Hypot(px-100, py-113) < w+0.6
		default:
			glyph = seg(91, 91, 109, 109) < w || seg(91, 109, 109, 91) < w
		}
		if glyph {
			return white
		}
		return [...]color.RGBA{
			stateOK:   {0x26, 0xa2, 0x69, 0xff},
			stateWarn: {0xc6, 0x46, 0x00, 0xff},
			stateBad:  {0xc0, 0x1c, 0x28, 0xff},
		}[state]
	}

	half, dx := shieldHalf(py), math.Abs(px-64)
	if half == 0 || dx > half {
		return color.RGBA{}
	}
	// border: within 9 units of the edge (sides, top slope or bottom curve)
	if half-dx < 9 || py < 17 || shieldHalf(py+9) < dx+0.5 {
		return dark
	}
	// prompt ">_"
	if seg(42, 50, 58, 64) < 5 || seg(58, 64, 42, 78) < 5 || seg(66, 82, 84, 82) < 5 {
		return dark
	}
	return white
}
