package agent

import (
	"slices"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestPrinterCommands(t *testing.T) {
	p := api.Printer{Name: "office", URI: "ipps://printer.example.com/ipp/print", Location: "2nd floor", Duplex: "two-sided-long-edge", PaperSize: "A4"}
	got := strings.Join(lpadminArgs(p), " ")
	want := "-p limdm-office -E -v ipps://printer.example.com/ipp/print -m everywhere -D office -o printer-is-shared=false -L 2nd floor -o sides-default=two-sided-long-edge -o media-default=A4"
	if got != want {
		t.Fatalf("\n%s\n%s", got, want)
	}
	p.PPD, p.Description = "drv:///sample.drv/generic.ppd", "Office"
	args := lpadminArgs(p)
	if i := slices.Index(args, "-m"); args[i+1] != p.PPD || !slices.Contains(args, "Office") {
		t.Fatal(args)
	}
	// the default flag alone does not recreate the queue
	d := p
	d.Default = true
	if printerHash(p) != printerHash(d) {
		t.Fatal("default changes the hash")
	}
	if d.PaperSize = "Letter"; printerHash(p) == printerHash(d) {
		t.Fatal("paper size does not change the hash")
	}
	q := parseLpstatQueues("device for limdm-office: ipps://printer.example.com/ipp/print\ndevice for HP_Home: usb://HP/X\nlpstat: No destinations added.\n")
	if len(q) != 1 || !q["limdm-office"] {
		t.Fatal(q)
	}
}
