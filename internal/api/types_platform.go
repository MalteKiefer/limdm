package api

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Platform types: printers (CUPS) and TPM facts.

const TypePrinters = "com.limdm.printers"

// PrinterPrefix marks the CUPS queues LiMDM manages; queues with it that are
// no longer declared are deleted, all others are left alone.
const PrinterPrefix = "limdm-"

type Printer struct {
	Name        string `json:"name"`                  // queue name after the limdm- prefix
	URI         string `json:"uri"`                   // ipp:// or ipps://; socket:// and lpd:// only with a PPD
	PPD         string `json:"ppd,omitempty"`         // model as lpinfo -m lists it; empty: driverless IPP Everywhere
	Package     string `json:"package,omitempty"`     // package that provides the PPD, installed first
	Location    string `json:"location,omitempty"`    // shown in print dialogs
	Description string `json:"description,omitempty"` // display name; defaults to the name
	Default     bool   `json:"default,omitempty"`     // system default printer
	Duplex      string `json:"duplex,omitempty"`      // one-sided | two-sided-long-edge | two-sided-short-edge
	PaperSize   string `json:"paper_size,omitempty"`  // A4, Letter, iso_a4_210x297mm ...
}

type Printers struct {
	Printers    []Printer `json:"printers"`
	InstallCUPS bool      `json:"install_cups,omitempty"` // install CUPS where it is missing; otherwise such devices are skipped
}

// TPMInfo is the TPM the inventory found in sysfs.
type TPMInfo struct {
	Present bool   `json:"present"`
	Version string `json:"version,omitempty"` // 2.0 or 1.2
	// LUKSBound lists LUKS devices with a systemd-tpm2 token.
	LUKSBound []string `json:"luks_bound,omitempty"`
}

// TPM2Binding binds LUKS volumes to the TPM with systemd-cryptenroll. The
// escrowed recovery key stays a valid key slot.
type TPM2Binding struct {
	PCRs    []int `json:"pcrs,omitempty"`    // PCR indexes the key is sealed to; default 7 (Secure Boot state)
	PIN     bool  `json:"pin,omitempty"`     // a PIN at boot: the user sets it with limdm-agent recovery-key
	Require bool  `json:"require,omitempty"` // the compliance check fails while a volume is not bound
}

// PCRList renders the PCRs for --tpm2-pcrs, "7" when none are declared.
func (b *TPM2Binding) PCRList() string {
	if len(b.PCRs) == 0 {
		return "7"
	}
	s := make([]string, len(b.PCRs))
	for i, p := range b.PCRs {
		s[i] = fmt.Sprint(p)
	}
	return strings.Join(s, "+")
}

func (b *TPM2Binding) validate() error {
	seen := map[int]bool{}
	for _, p := range b.PCRs {
		if p < 0 || p > 23 || seen[p] {
			return fmt.Errorf("tpm2: pcr %d must be 0..23 and listed once", p)
		}
		seen[p] = true
	}
	return nil
}

var (
	ppdRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,254}$`)
	paperRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,40}$`)
	duplexModes = []string{"one-sided", "two-sided-long-edge", "two-sided-short-edge"}
)

// Validate checks a printer. Every value ends up as a separate argument of
// lpadmin (no shell), but CUPS writes them into line based files, so control
// characters and quotes are refused as well.
func (p Printer) Validate() error {
	if !nameRe.MatchString(p.Name) {
		return fmt.Errorf("printer %q: name must be lower case letters, digits, . _ or -", p.Name)
	}
	u, err := url.Parse(p.URI)
	if err != nil || u.Host == "" || u.User != nil || len(p.URI) > 512 || strings.ContainsAny(p.URI, " \t\r\n'\"\\`") || !noControl(p.URI, 512) {
		return fmt.Errorf("printer %q: uri must be a URL with a host and without credentials", p.Name)
	}
	switch u.Scheme {
	case "ipp", "ipps":
	case "socket", "lpd":
		if p.PPD == "" {
			return fmt.Errorf("printer %q: %s needs a ppd; driverless queues use ipp or ipps", p.Name, u.Scheme)
		}
	default:
		return fmt.Errorf("printer %q: uri scheme must be ipp, ipps, socket or lpd", p.Name)
	}
	if p.PPD != "" && (!ppdRe.MatchString(p.PPD) || strings.Contains(p.PPD, "..")) {
		return fmt.Errorf("printer %q: invalid ppd %q", p.Name, p.PPD)
	}
	if p.Package != "" && !pkgNameRe.MatchString(p.Package) {
		return fmt.Errorf("printer %q: invalid package %q", p.Name, p.Package)
	}
	for _, s := range []string{p.Location, p.Description} {
		if !noControl(s, 128) || strings.ContainsAny(s, "\n\t\"\\") {
			return fmt.Errorf("printer %q: location and description up to 128 characters, one line, no quotes", p.Name)
		}
	}
	if p.Duplex != "" && !slices.Contains(duplexModes, p.Duplex) {
		return fmt.Errorf("printer %q: duplex must be one of %s", p.Name, strings.Join(duplexModes, ", "))
	}
	if p.PaperSize != "" && !paperRe.MatchString(p.PaperSize) {
		return fmt.Errorf("printer %q: invalid paper_size %q", p.Name, p.PaperSize)
	}
	return nil
}

func init() {
	Types[TypePrinters] = `{"printers": [{"name": "office", "uri": "ipps://printer.example.com/ipp/print", "location": "2nd floor", "description": "Office printer", "default": true, "duplex": "two-sided-long-edge", "paper_size": "A4"}], "install_cups": false}`
}

// applyPlatform decodes and validates the platform types.
func (d Declaration) applyPlatform(p *Policy) (bool, error) {
	switch d.Type {
	case TypePrinters:
		var v Printers
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		if len(v.Printers) > 100 {
			return true, errors.New("at most 100 printers")
		}
		var errs []error
		names, defaults := map[string]bool{}, 0
		for _, pr := range v.Printers {
			errs = append(errs, pr.Validate())
			if names[pr.Name] {
				errs = append(errs, fmt.Errorf("printer %q is listed twice", pr.Name))
			}
			names[pr.Name] = true
			if pr.Default {
				defaults++
			}
		}
		if defaults > 1 {
			errs = append(errs, errors.New("only one printer can be the default"))
		}
		p.Extra.Printers = &v
		return true, errors.Join(errs...)
	}
	return d.applyArtifacts(p) // artifacts.go
}
