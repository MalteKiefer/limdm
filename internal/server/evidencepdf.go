package server

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"
)

// The PDF evidence report: score, frameworks, device states, failing
// checks, active risk exceptions and the SHA-256 and signature of the
// bundle it was rendered from. A small PDF 1.4 writer with the standard
// Helvetica fonts (WinAnsi), no dependency and no external service.

type pdfWriter struct {
	pages []*bytes.Buffer
	y     float64
}

const (
	pdfW, pdfH, pdfMargin = 595.0, 842.0, 50.0
	pdfBottom             = 60.0
)

func (p *pdfWriter) page() *bytes.Buffer {
	if len(p.pages) == 0 || p.y < pdfBottom {
		p.pages = append(p.pages, &bytes.Buffer{})
		p.y = pdfH - pdfMargin
	}
	return p.pages[len(p.pages)-1]
}

// pdfText encodes s for a WinAnsi string literal: Latin-1 runes as bytes
// (umlauts, ß), everything else as '?', with ( ) \ escaped.
func pdfText(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '(' || r == ')' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '…':
			b.WriteByte(0x85) // WinAnsi ellipsis
		case r == '\n' || r == '\t':
			b.WriteByte(' ')
		case r >= 32 && r < 127, r >= 160 && r < 256:
			b.WriteByte(byte(r))
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

// fit cuts s to about the width of w points at the font size (Helvetica
// averages half the size per character).
func fit(s string, w, size float64) string {
	n := int(w / (size * 0.5))
	if r := []rune(s); len(r) > n && n > 1 {
		return string(r[:n-1]) + "…"
	}
	return s
}

// row writes cells at the x offsets (points from the margin); the last
// cell takes the rest of the line.
func (p *pdfWriter) row(size float64, bold bool, xs []float64, cells ...string) {
	pg := p.page()
	font := "F1"
	if bold {
		font = "F2"
	}
	for i, c := range cells {
		w := pdfW - 2*pdfMargin - xs[i]
		if i+1 < len(xs) {
			w = xs[i+1] - xs[i] - 6
		}
		fmt.Fprintf(pg, "BT /%s %.1f Tf %.1f %.1f Td (%s) Tj ET\n", font, size, pdfMargin+xs[i], p.y, pdfText(fit(c, w, size)))
	}
	p.y -= size * 1.5
}

func (p *pdfWriter) line(size float64, bold bool, s string) { p.row(size, bold, []float64{0}, s) }

// wrap writes s over as many lines as it needs.
func (p *pdfWriter) wrap(size float64, s string) {
	n := int((pdfW - 2*pdfMargin) / (size * 0.5))
	for len(s) > 0 {
		cut := min(len(s), n)
		if cut < len(s) {
			if i := strings.LastIndexAny(s[:cut], " ,"); i > n/2 {
				cut = i + 1
			}
		}
		p.line(size, false, strings.TrimSpace(s[:cut]))
		s = s[cut:]
	}
}

func (p *pdfWriter) heading(s string) {
	p.y -= 8
	if p.y < pdfBottom+60 { // keep a heading with its first rows
		p.y = 0
	}
	p.line(13, true, s)
	p.y -= 2
}

// bar draws a pass rate as a gray bar with its value written next to it.
func (p *pdfWriter) bar(x, w, rate float64) {
	pg := p.page()
	y := p.y - 1
	fmt.Fprintf(pg, "0.88 g %.1f %.1f %.1f 7 re f 0.2 g %.1f %.1f %.1f 7 re f 0 g\n", pdfMargin+x, y, w, pdfMargin+x, y, w*rate/100)
}

func (p *pdfWriter) bytes() []byte {
	var out bytes.Buffer
	var offs []int
	obj := func(body string) {
		offs = append(offs, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", len(offs), body)
	}
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	n := len(p.pages)
	kids := make([]string, n)
	for i := range n {
		kids[i] = fmt.Sprintf("%d 0 R", 5+2*i)
	}
	obj("<< /Type /Catalog /Pages 2 0 R >>")
	obj(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), n))
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
	for i, pg := range p.pages {
		footer := fmt.Sprintf("BT /F1 8 Tf %.1f 30 Td (LiMDM %d / %d) Tj ET\n", pdfMargin, i+1, n)
		obj(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>", pdfW, pdfH, 6+2*i))
		content := pg.String() + footer
		obj(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content))
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offs)+1)
	for _, o := range offs {
		fmt.Fprintf(&out, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offs)+1, xref)
	return out.Bytes()
}

// evidencePDF renders the report of a bundle in lang; sum is the SHA-256
// of the signed bundle file.
func evidencePDF(lang string, b evidenceBundle, sum string, sig evidenceSignature) []byte {
	tr := func(s string) string { return translate(lang, s) }
	p := &pdfWriter{}
	p.line(18, true, tr("LiMDM compliance evidence"))
	p.y -= 4
	scope := tr("global view")
	if b.Tenant != 0 {
		scope = fmt.Sprintf("%s %d", tr("tenant"), b.Tenant)
	}
	p.line(9, false, fmt.Sprintf("%s %s · %s %s · %s", tr("Generated"), b.GeneratedAt.Format(time.RFC3339), tr("by"), b.GeneratedBy, scope))
	p.line(9, false, fmt.Sprintf("%s: %d %s", tr("History window"), b.WindowDays, tr("days")))

	p.heading(tr("Score"))
	p.line(22, true, fmt.Sprintf("%.1f %%", b.Score))
	p.wrap(9, tr("Share of reporting devices that pass every check"))
	cols := []float64{0, 130, 260, 390}
	p.row(9, true, cols, tr("Compliant"), tr("Non-compliant"), tr("Stale"), tr("Pending"))
	p.row(10, false, cols, fmt.Sprint(b.Compliant), fmt.Sprint(b.NonCompliant), fmt.Sprint(b.Stale), fmt.Sprint(b.Pending))

	p.heading(tr("Frameworks"))
	fcols := []float64{0, 170, 300, 360, 420}
	p.row(9, true, fcols, tr("Framework"), tr("Pass rate"), tr("Pass"), tr("Fail"), "")
	for _, f := range b.Frameworks {
		p.bar(170+45, 80, f.Rate)
		p.row(9, false, fcols, f.Name, fmt.Sprintf("%.1f %%", f.Rate), fmt.Sprint(f.Pass), fmt.Sprint(f.Fail), "")
	}

	p.heading(tr("Failing checks"))
	type agg struct {
		id, title string
		fail      int
	}
	m := map[string]*agg{}
	for _, d := range b.Devices {
		for _, c := range d.Checks {
			if c.Status == "fail" {
				if m[c.ID] == nil {
					m[c.ID] = &agg{c.ID, tr(c.Title), 0}
				}
				m[c.ID].fail++
			}
		}
	}
	var fails []*agg
	for _, a := range m {
		fails = append(fails, a)
	}
	slices.SortFunc(fails, func(x, y *agg) int { return cmpFail(y.fail, x.fail, x.id, y.id) })
	ccols := []float64{0, 150, 440}
	if len(fails) == 0 {
		p.line(9, false, tr("No failing checks."))
	} else {
		p.row(9, true, ccols, tr("Check"), tr("Title"), tr("Devices"))
		for _, a := range fails {
			p.row(9, false, ccols, a.id, a.title, fmt.Sprint(a.fail))
		}
	}

	p.heading(tr("Active risk exceptions"))
	ecols := []float64{0, 110, 165, 225, 300, 375, 435}
	n := 0
	for _, e := range b.Exceptions {
		if e.State != "active" {
			continue
		}
		if n == 0 {
			p.row(8, true, ecols, tr("Check"), tr("Mode"), tr("Devices"), tr("Risk owner"), tr("Approver"), tr("Expires"), tr("Reason"))
		}
		n++
		tag := e.Tag
		if tag == "" {
			tag = tr("all")
		}
		p.row(8, false, ecols, e.CheckID, tr(e.Mode), tag, e.Owner, e.Approver, e.Expires.AddDate(0, 0, -1).Format(time.DateOnly), e.Reason)
	}
	if n == 0 {
		p.line(9, false, tr("No active risk exceptions."))
	}

	p.heading(tr("Versions"))
	p.line(9, false, tr("Check catalog")+": "+versionList(b.CatalogVersions))
	p.line(9, false, tr("Agent")+": "+versionList(b.AgentVersions))

	p.heading(tr("Signature"))
	p.wrap(9, tr("This report was rendered from a signed evidence bundle. Download evidence.json and check it with limdm-server evidence verify FILE; the bundle written for this report is in the audit log as evidence.sign with this SHA-256."))
	p.line(8, true, tr("Bundle SHA-256"))
	p.line(8, false, sum)
	p.line(8, true, tr("Command key (SHA-256 of the Ed25519 public key)"))
	p.line(8, false, sig.KeyID)
	p.line(8, true, tr("Signature (Ed25519)"))
	p.line(8, false, sig.Value[:min(64, len(sig.Value))])
	if len(sig.Value) > 64 {
		p.line(8, false, sig.Value[64:])
	}
	return p.bytes()
}

func cmpFail(a, b int, x, y string) int {
	if a != b {
		return a - b
	}
	return strings.Compare(x, y)
}

func versionList(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s (%d)", cmp.Or(k, "?"), m[k])
	}
	return strings.Join(parts, ", ")
}
