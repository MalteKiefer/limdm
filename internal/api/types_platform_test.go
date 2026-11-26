package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPrintersValidation(t *testing.T) {
	var p Policy
	if _, err := (Declaration{Type: TypePrinters, Payload: json.RawMessage(Types[TypePrinters])}).applyPlatform(&p); err != nil || p.Extra.Printers == nil {
		t.Fatalf("example: %v", err)
	}
	ok := Printer{Name: "office", URI: "ipp://10.0.0.5/ipp/print"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Printer{
		{Name: "Office Printer", URI: ok.URI},
		{Name: "x", URI: "ipp://host/print; rm -rf /"},
		{Name: "x", URI: "ipp://host/$(id)'"},
		{Name: "x", URI: "ipp://user:secret@host/print"},
		{Name: "x", URI: "file:///dev/null"},
		{Name: "x", URI: "socket://10.0.0.5:9100"}, // needs a ppd
		{Name: "x", URI: ok.URI, PPD: "../../etc/shadow"},
		{Name: "x", URI: ok.URI, PPD: "-x"},
		{Name: "x", URI: ok.URI, Package: "-oops"},
		{Name: "x", URI: ok.URI, Location: "a\nb"},
		{Name: "x", URI: ok.URI, Duplex: "both"},
		{Name: "x", URI: ok.URI, PaperSize: "A4 -o x"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if err := (Printer{Name: "x", URI: "socket://10.0.0.5:9100", PPD: "drv:///sample.drv/generic.ppd", Package: "cups-filters"}).Validate(); err != nil {
		t.Fatal(err)
	}
	two := `{"printers": [{"name": "a", "uri": "ipp://h/a", "default": true}, {"name": "a", "uri": "ipp://h/b", "default": true}]}`
	_, err := (Declaration{Type: TypePrinters, Payload: json.RawMessage(two)}).applyPlatform(&p)
	if err == nil || !strings.Contains(err.Error(), "twice") || !strings.Contains(err.Error(), "default") {
		t.Fatal(err)
	}
}

func TestTPM2Binding(t *testing.T) {
	if s := (&TPM2Binding{}).PCRList(); s != "7" {
		t.Fatal(s)
	}
	if s := (&TPM2Binding{PCRs: []int{0, 7}}).PCRList(); s != "0+7" {
		t.Fatal(s)
	}
	for _, pcrs := range [][]int{{24}, {-1}, {7, 7}} {
		if (&TPM2Binding{PCRs: pcrs}).validate() == nil {
			t.Errorf("accepted %v", pcrs)
		}
	}
	var p Policy
	d := Declaration{Type: TypeDiskEncryption, Payload: json.RawMessage(`{"escrow": true, "rotate_after_view": true, "tpm2": {"pcrs": [7, 30]}}`)}
	if _, err := d.applySecurity(&p); err == nil {
		t.Fatal("pcr 30 accepted")
	}
}

func TestSUSERepository(t *testing.T) {
	r := Repository{Name: "vendor", Family: "suse", URL: "https://repo.example.com/rpm", KeyFile: "/usr/lib/rpm/gnupg/keys/gpg-pubkey-29b700a4-62b07e22.asc"}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r.Family = "gentoo"
	if r.Validate() == nil {
		t.Fatal("unknown family accepted")
	}
}
