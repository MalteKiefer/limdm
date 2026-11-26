// limdm is the command line counterpart of the LiMDM desktop app: what the
// app shows and does, a user (or an administrator over SSH) gets here too.
// It talks to the agent over its local socket, with the same rights as the
// app: the agent answers users with an active local session, and root.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/maltekiefer/limdm/internal/agent"
)

const usage = `usage: limdm COMMAND [options]

  info                          device, agent, compliance, profiles, certificates
  checks                        compliance checks of this device
  profiles                      configuration in force (declarations)
  certificates                  managed certificates
  log [-n 50]                   latest entries of the agent log
  sync                          check in with the server now

  software list                 the company catalog and what is installed
  software install APP          install an app of the catalog
  software remove APP           remove an app of the catalog
  software request APP [--note TEXT]
                                ask IT for an app that needs approval
  software search QUERY         search apps outside the catalog (Flathub)
  software request-new FLATPAK_ID [--remote flathub] [--name NAME] [--note TEXT]
                                ask IT for an app outside the catalog
  software requests             your requests for apps outside the catalog

  sso [status]                  company account of your session
  sso confirm                   confirm the company account (opens a sign in)
  recovery-key                  create the disk recovery key IT asks for

  version

Add --json to info, checks, profiles, certificates, log and software list
for machine readable output.`

var socket = "/run/limdm/agent.sock" // tests point it elsewhere

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		fmt.Println(usage)
		return
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(cmd string, args []string) error {
	switch cmd {
	case "version":
		fmt.Println(agent.Version)
		return nil
	case "info", "status":
		return info(args)
	case "checks":
		return checks(args)
	case "profiles":
		return profiles(args)
	case "certificates", "certs":
		return certificates(args)
	case "log":
		return logLines(args)
	case "sync":
		if _, err := call(agent.DesktopRequest{Op: "sync"}); err != nil {
			return err
		}
		fmt.Println("check in requested")
		return nil
	case "software", "apps":
		if len(args) == 0 {
			return software("list", nil)
		}
		return software(args[0], args[1:])
	case "sso":
		sub := "status"
		if len(args) > 0 {
			sub = args[0]
		}
		return sso(sub)
	case "recovery-key":
		return recoveryKey()
	}
	return fmt.Errorf("unknown command %q (limdm help)", cmd)
}

// call sends one request and reads one answer; errors of the agent come back
// as Go errors.
func call(req agent.DesktopRequest) (agent.DesktopResponse, error) {
	var resp agent.DesktopResponse
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "unix", socket)
	if err != nil {
		return resp, fmt.Errorf("the LiMDM agent does not answer (%w); is it running?", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Minute))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return resp, err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return resp, err
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return resp, err
	}
	if resp.Error != "" {
		if resp.Error == "not allowed" {
			return resp, errors.New("not allowed: only users signed in at this device, and root, may ask the agent")
		}
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// jsonFlag strips --json from args.
func jsonFlag(args []string) ([]string, bool) {
	out := slices.DeleteFunc(slices.Clone(args), func(a string) bool { return a == "--json" || a == "-json" })
	return out, len(out) != len(args)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func table() *tabwriter.Writer { return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0) }

func when(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	return t.Local().Format("2006-01-02 15:04") + " (" + ago(*t) + ")"
}

func ago(t time.Time) string {
	d := time.Since(t).Round(time.Minute)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func info(args []string) error {
	_, asJSON := jsonFlag(args)
	resp, err := call(agent.DesktopRequest{Op: "info"})
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(resp)
	}
	w := table()
	if resp.Company != "" {
		fmt.Fprintf(w, "Managed by\t%s\n", resp.Company)
	}
	if st := resp.Status; st != nil {
		sys := st.System
		fmt.Fprintf(w, "Hostname\t%s\n", st.Hostname)
		row(w, "System", strings.TrimSpace(sys.OS+" "+sys.Arch))
		row(w, "Kernel", sys.Kernel)
		row(w, "Hardware", strings.TrimSpace(sys.Vendor+" "+sys.Model))
		row(w, "Serial number", sys.Serial)
		fmt.Fprintf(w, "\t\n")
		fmt.Fprintf(w, "Device ID\t%s\n", st.DeviceID)
		fmt.Fprintf(w, "Server\t%s\n", st.Server)
		fmt.Fprintf(w, "Agent\t%s\n", st.Version)
		row(w, "Inventory", sys.Inventory)
		fmt.Fprintf(w, "Last check in\t%s\n", when(st.LastCheckin))
		if st.CheckinEvery > 0 {
			fmt.Fprintf(w, "Check in every\t%s (and at once when IT sends a command)\n", time.Duration(st.CheckinEvery)*time.Second)
		}
		if st.LastError != "" {
			fmt.Fprintf(w, "Last error\t%s\n", st.LastError)
		}
		if st.QueuedEvents+st.QueuedResults > 0 {
			fmt.Fprintf(w, "Waiting to send\t%d events, %d command results\n", st.QueuedEvents, st.QueuedResults)
		}
		fmt.Fprintf(w, "Declarations\t%d (token %s)\n", st.Declarations, st.DeclToken)
		row(w, "Updates", st.Updates)
		if st.LastUpdateRun != nil {
			fmt.Fprintf(w, "Last update run\t%s\n", when(st.LastUpdateRun))
		}
		fmt.Fprintf(w, "Desktop login\t%s\n", st.DesktopLogin)
		fmt.Fprintf(w, "Remote scripts\t%s\n", map[bool]string{true: "allowed", false: "not allowed"}[st.ScriptsAllow])
		if st.OfflineLockH > 0 {
			fmt.Fprintf(w, "Offline lock\tafter %d h without the server\n", st.OfflineLockH)
		}
		switch {
		case st.LostMode:
			fmt.Fprintf(w, "Device lock\tlost mode\n")
		case st.OfflineLocked:
			fmt.Fprintf(w, "Device lock\tlocked: no server contact for too long\n")
		case st.Locked:
			fmt.Fprintf(w, "Device lock\tlocked by IT\n")
		}
		fmt.Fprintf(w, "\t\n")
		state := "compliant"
		if len(st.Failing) > 0 {
			state = fmt.Sprintf("%d of %d checks failing", len(st.Failing), st.Checks)
		} else if st.Checks == 0 {
			state = "no compliance checks declared"
		}
		fmt.Fprintf(w, "Compliance\t%s\n", state)
		for _, f := range st.Failing {
			fmt.Fprintf(w, "\t  failing: %s\n", f)
		}
		fmt.Fprintf(w, "Recovery keys\t%d escrowed\n", st.Escrowed)
	}
	for _, v := range resp.Need {
		fmt.Fprintf(w, "Action needed\trecovery key for %s (run: limdm recovery-key)\n", v.Device)
	}
	fmt.Fprintf(w, "Profiles\t%d in force (limdm profiles)\n", len(resp.Profiles))
	fmt.Fprintf(w, "Certificates\t%d managed (limdm certificates)\n", len(resp.Certs))
	if s, err := call(agent.DesktopRequest{Op: "sso-status"}); err == nil && s.SSO != nil && s.SSO.Managed {
		fmt.Fprintf(w, "Company account\t%s\n", ssoLine(s.SSO))
	}
	return w.Flush()
}

// row prints a line only when there is a value.
func row(w io.Writer, label, value string) {
	if value != "" {
		fmt.Fprintf(w, "%s\t%s\n", label, value)
	}
}

func checks(args []string) error {
	_, asJSON := jsonFlag(args)
	resp, err := call(agent.DesktopRequest{Op: "info"})
	if err != nil {
		return err
	}
	var list []agent.DesktopCheck
	if resp.Status != nil {
		list = resp.Status.CheckList
	}
	if asJSON {
		return printJSON(list)
	}
	if len(list) == 0 {
		fmt.Println("no compliance checks declared for this device")
		return nil
	}
	w := table()
	fmt.Fprintln(w, "STATUS\tCHECK\tDETAIL")
	for _, c := range list {
		fmt.Fprintf(w, "%s\t%s\t%s\n", strings.ToUpper(c.Status), c.Title, c.Detail)
	}
	return w.Flush()
}

func profiles(args []string) error {
	rest, asJSON := jsonFlag(args)
	resp, err := call(agent.DesktopRequest{Op: "info"})
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(resp.Profiles)
	}
	verbose := slices.Contains(rest, "-v") || slices.Contains(rest, "--verbose")
	w := table()
	fmt.Fprintln(w, "STATE\tTYPE\tIDENTIFIER")
	for _, p := range resp.Profiles {
		state := "active"
		if !p.Active {
			state = "not achieved"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", state, p.Type, p.Identifier)
		for _, r := range p.Reasons {
			fmt.Fprintf(w, "\t\t  %s\n", r)
		}
	}
	if err := w.Flush(); err != nil || !verbose {
		return err
	}
	for _, p := range resp.Profiles {
		fmt.Printf("\n%s (%s)\n%s\n", p.Identifier, p.Type, p.Settings)
	}
	return nil
}

func certificates(args []string) error {
	_, asJSON := jsonFlag(args)
	resp, err := call(agent.DesktopRequest{Op: "info"})
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(resp.Certs)
	}
	if len(resp.Certs) == 0 {
		fmt.Println("no managed certificates")
		return nil
	}
	w := table()
	fmt.Fprintln(w, "NAME\tSUBJECT\tVALID UNTIL\tSHA-256")
	for _, c := range resp.Certs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.Name, c.Subject, c.NotAfter.Local().Format("2006-01-02"), c.SHA256)
	}
	return w.Flush()
}

func logLines(args []string) error {
	rest, asJSON := jsonFlag(args)
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	n := fs.Int("n", 50, "number of entries")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	resp, err := call(agent.DesktopRequest{Op: "info"})
	if err != nil {
		return err
	}
	lines := resp.LogLines
	if *n > 0 && len(lines) > *n {
		lines = lines[len(lines)-*n:]
	}
	if asJSON {
		return printJSON(lines)
	}
	for _, l := range lines {
		fmt.Printf("%s  %-7s  %s\n", l.Time.Local().Format("2006-01-02 15:04:05"), l.Level, l.Text)
	}
	return nil
}

// ---- software ----

func software(sub string, args []string) error {
	rest, asJSON := jsonFlag(args)
	fs := flag.NewFlagSet("software "+sub, flag.ContinueOnError)
	note := fs.String("note", "", "a note for IT")
	remote := fs.String("remote", "", "Flatpak remote of the app (request-new)")
	name := fs.String("name", "", "display name (request-new)")
	pos, flags := splitArgs(rest)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	switch sub {
	case "list", "ls":
		resp, err := call(agent.DesktopRequest{Op: "catalog"})
		if err != nil {
			return err
		}
		if asJSON {
			return printJSON(resp)
		}
		return listApps(resp)
	case "install", "remove", "request":
		if len(pos) != 1 {
			return fmt.Errorf("usage: limdm software %s APP", sub)
		}
		id, err := findApp(pos[0])
		if err != nil {
			return err
		}
		if _, err := call(agent.DesktopRequest{Op: "app-" + sub, App: id, Note: *note}); err != nil {
			return err
		}
		switch sub {
		case "request":
			fmt.Println("request sent to IT; it shows up in limdm software list once decided")
		default:
			fmt.Printf("%s of %s started; follow it with: limdm software list\n", sub, id)
		}
		return nil
	case "search":
		if len(pos) == 0 {
			return errors.New("usage: limdm software search QUERY")
		}
		resp, err := call(agent.DesktopRequest{Op: "search", Query: strings.Join(pos, " ")})
		if err != nil {
			return err
		}
		if asJSON {
			return printJSON(resp.Hits)
		}
		if len(resp.Hits) == 0 {
			fmt.Println("nothing found, or everything found is in the catalog already (limdm software list)")
			return nil
		}
		w := table()
		fmt.Fprintln(w, "FLATPAK ID\tNAME\tSUMMARY")
		for _, h := range resp.Hits {
			fmt.Fprintf(w, "%s\t%s\t%s\n", h.ID, h.Name, h.Summary)
		}
		fmt.Fprintln(w, "\nask IT for one: limdm software request-new FLATPAK_ID --note \"why\"")
		return w.Flush()
	case "request-new":
		if len(pos) != 1 {
			return errors.New("usage: limdm software request-new FLATPAK_ID [--remote flathub] [--name NAME] [--note TEXT]")
		}
		if _, err := call(agent.DesktopRequest{Op: "app-request-new", Flatpak: pos[0], Remote: *remote, Name: *name, Note: *note}); err != nil {
			return err
		}
		fmt.Println("request sent to IT; follow it with: limdm software requests")
		return nil
	case "requests":
		resp, err := call(agent.DesktopRequest{Op: "catalog"})
		if err != nil {
			return err
		}
		if asJSON {
			return printJSON(resp.Requests)
		}
		if len(resp.Requests) == 0 {
			fmt.Println("no requests for apps outside the catalog")
			return nil
		}
		w := table()
		fmt.Fprintln(w, "STATUS\tFLATPAK ID\tNAME")
		for _, r := range resp.Requests {
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Status, r.Flatpak, r.Name)
		}
		return w.Flush()
	}
	return fmt.Errorf("unknown software command %q (limdm help)", sub)
}

// splitArgs separates positional arguments from flags, so flags may follow
// the app name (limdm software request vlc --note "for a course").
func splitArgs(args []string) (pos, flags []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return pos, flags
}

func listApps(resp agent.DesktopResponse) error {
	if len(resp.Apps) == 0 {
		fmt.Println("the company catalog is empty for this device")
		return nil
	}
	w := table()
	fmt.Fprintln(w, "APP\tNAME\tSTATE\tAVAILABILITY")
	for _, a := range resp.Apps {
		state := "not installed"
		switch {
		case a.Busy != "":
			state = a.Busy + " running"
		case a.Error != "":
			state = "failed: " + a.Error
		case a.Installed:
			state = "installed"
			if a.Via != "" {
				state += " (" + a.Via + ")"
			}
		}
		avail := map[string]string{"available": "install yourself", "request": "on request", "required": "required by IT"}[a.Mode]
		if avail == "" {
			avail = a.Mode
		}
		if a.Request != "" {
			avail += ", request " + a.Request
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.ID, a.Name, state, avail)
	}
	if s := resp.Store; s != nil && s.ReadOnly {
		fmt.Fprintln(w, "\nsoftware centers are read only on this device: install through this catalog")
	}
	return w.Flush()
}

// findApp resolves an app ID or name of the catalog.
func findApp(q string) (string, error) {
	resp, err := call(agent.DesktopRequest{Op: "catalog"})
	if err != nil {
		return "", err
	}
	var hits []string
	for _, a := range resp.Apps {
		if strings.EqualFold(a.ID, q) {
			return a.ID, nil
		}
		if strings.EqualFold(a.Name, q) {
			hits = append(hits, a.ID)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return "", fmt.Errorf("%q is not in the catalog (limdm software list, or limdm software search)", q)
	}
	return "", fmt.Errorf("%q matches several apps: %s", q, strings.Join(hits, ", "))
}

// ---- company account and recovery key ----

func ssoLine(s *agent.SSOStatus) string {
	switch {
	case s.Running:
		return "confirmation running"
	case s.Due:
		return s.Email + ": confirmation due (limdm sso confirm)"
	case s.Confirmed != nil:
		line := s.Email + ": confirmed " + ago(*s.Confirmed)
		if s.Deadline != nil {
			line += ", next by " + s.Deadline.Local().Format("2006-01-02")
		}
		return line
	}
	return s.Email + ": not confirmed yet (limdm sso confirm)"
}

func sso(sub string) error {
	switch sub {
	case "status":
		resp, err := call(agent.DesktopRequest{Op: "sso-status"})
		if err != nil {
			return err
		}
		if resp.SSO == nil || !resp.SSO.Managed {
			fmt.Println("your account is not managed by the company directory on this device")
			return nil
		}
		fmt.Println(ssoLine(resp.SSO))
		return nil
	case "confirm":
		resp, err := call(agent.DesktopRequest{Op: "sso-confirm"})
		if err != nil {
			return err
		}
		if resp.SSO == nil || !resp.SSO.Managed {
			return errors.New("your account is not managed by the company directory on this device")
		}
		fmt.Printf("Open %s and enter the code %s\n", resp.SSO.URI, resp.SSO.Code)
		fmt.Println("waiting for the sign in (Ctrl+C stops waiting, the sign in stays valid) …")
		for range 120 { // ten minutes, the lifetime of the device code
			time.Sleep(5 * time.Second)
			st, err := call(agent.DesktopRequest{Op: "sso-status"})
			if err != nil {
				return err
			}
			if s := st.SSO; s != nil && !s.Running {
				if s.Error != "" {
					return errors.New(s.Error)
				}
				fmt.Println("confirmed")
				return nil
			}
		}
		return errors.New("no sign in within ten minutes")
	}
	return fmt.Errorf("unknown sso command %q (status or confirm)", sub)
}

func recoveryKey() error {
	resp, err := call(agent.DesktopRequest{Op: "status"})
	if err != nil {
		return err
	}
	if len(resp.Need) == 0 {
		fmt.Println("no recovery key is needed on this device")
		return nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("the passphrase is read from a terminal only")
	}
	for _, v := range resp.Need {
		fmt.Fprintf(os.Stderr, "Disk passphrase of %s: ", v.Device)
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		if _, err := call(agent.DesktopRequest{Op: "escrow", UUID: v.UUID, Passphrase: string(pw)}); err != nil {
			return fmt.Errorf("%s: %w", v.Device, err)
		}
		fmt.Printf("recovery key for %s created; it reaches IT with the next check in\n", v.Device)
	}
	return nil
}
