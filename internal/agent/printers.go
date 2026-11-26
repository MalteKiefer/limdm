package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/maltekiefer/limdm/internal/api"
)

// Printers are CUPS queues set up with lpadmin, always with exec arguments,
// never a shell. A queue is only (re)created when its declaration changed:
// lpadmin -m everywhere asks the printer for its capabilities, which fails
// while it is switched off. printerState keeps a hash per applied queue.

const printerState = stateDir + "/printers.json"

// lpadminArgs defines one queue: enabled, accepting jobs, not shared.
func lpadminArgs(p api.Printer) []string {
	model := "everywhere" // driverless IPP Everywhere
	if p.PPD != "" {
		model = p.PPD
	}
	desc := p.Description
	if desc == "" {
		desc = p.Name
	}
	args := []string{"-p", api.PrinterPrefix + p.Name, "-E", "-v", p.URI, "-m", model, "-D", desc, "-o", "printer-is-shared=false"}
	if p.Location != "" {
		args = append(args, "-L", p.Location)
	}
	if p.Duplex != "" {
		args = append(args, "-o", "sides-default="+p.Duplex)
	}
	if p.PaperSize != "" {
		args = append(args, "-o", "media-default="+p.PaperSize)
	}
	return args
}

// printerHash identifies a queue definition; the default flag is set apart.
func printerHash(p api.Printer) string {
	p.Default = false
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// parseLpstatQueues returns the managed queues of "lpstat -v".
func parseLpstatQueues(out string) map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(l, "device for ")
		if name, _, found := strings.Cut(rest, ":"); ok && found && strings.HasPrefix(name, api.PrinterPrefix) {
			m[name] = true
		}
	}
	return m
}

func (a *Agent) applyPrinters(ps *api.Printers) error {
	var want []api.Printer
	if ps != nil {
		want = ps.Printers
	}
	if !hasCmd("lpadmin") {
		if len(want) == 0 || !ps.InstallCUPS {
			return nil // no CUPS on this device and none requested
		}
		if err := a.host.install("cups"); err != nil {
			return err
		}
		if err := svc("enable-now", "cups"); err != nil {
			return err
		}
		a.event("installed CUPS for the printer declaration")
	}
	applied := map[string]string{}
	if b, err := os.ReadFile(printerState); err == nil {
		_ = json.Unmarshal(b, &applied) // unreadable: every queue is set up again
	}
	out, _ := sh("lpstat", "-v") // exits non zero without any queue
	existing := parseLpstatQueues(out)
	var errs []error
	next, desired := map[string]string{}, map[string]bool{}
	for _, p := range want {
		q, h := api.PrinterPrefix+p.Name, printerHash(p)
		desired[q] = true
		if applied[q] == h && existing[q] {
			next[q] = h
			continue
		}
		if p.Package != "" && !a.host.isInstalled(p.Package) {
			if err := a.host.install(p.Package); err != nil {
				errs = append(errs, fmt.Errorf("printer %s: %w", p.Name, err))
				continue
			}
		}
		if out, err := sh("lpadmin", lpadminArgs(p)...); err != nil {
			errs = append(errs, fmt.Errorf("printer %s: lpadmin: %s", p.Name, lastLines(out, 2)))
			continue
		}
		next[q] = h
		a.event("printer %s set up", q)
	}
	for q := range existing {
		if desired[q] {
			continue
		}
		if out, err := sh("lpadmin", "-x", q); err != nil {
			errs = append(errs, fmt.Errorf("removing printer %s: %s", q, lastLines(out, 2)))
			continue
		}
		a.event("printer %s removed", q)
	}
	for _, p := range want {
		q := api.PrinterPrefix + p.Name
		if !p.Default || next[q] == "" {
			continue
		}
		if cur, _ := sh("lpstat", "-d"); strings.TrimSpace(cur) != "system default destination: "+q {
			if out, err := sh("lpadmin", "-d", q); err != nil {
				errs = append(errs, fmt.Errorf("default printer %s: %s", q, lastLines(out, 2)))
			}
		}
	}
	if len(next) == 0 {
		if err := os.Remove(printerState); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}
	b, _ := json.Marshal(next)
	_, err := writeIfChanged(printerState, string(b), 0o600)
	return errors.Join(append(errs, err)...)
}
