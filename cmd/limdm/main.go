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
	"github.com/maltekiefer/limdm/internal/locale"
)

// lang is the language of human readable output (LANG, LC_MESSAGES, ...);
// JSON output, exit codes and status codes stay the same in every language.
var lang = locale.System()

func tr(msg string, args ...any) string { return locale.T(lang, msg, args...) }

func trn(n int, one, other string, args ...any) string {
	return locale.N(lang, n, one, other, args...)
}

func usage() string {
	return tr(`usage: limdm COMMAND [options]

  info                          device, agent, compliance, blueprint, certificates
  checks [--strict]             compliance checks of this device, failing first;
                                --strict exits with 2 when a check fails
  blueprint [-v]                settings of the blueprint in force (declarations)
  certificates                  managed certificates
  log [-n 50]                   latest entries of the agent log
  sync                          sync with the server now

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
  support end                   end the remote support session IT opened

  version

Add --json to info, checks, blueprint, certificates, log and software list
for machine readable output.`)
}

var socket = "/run/limdm/agent.sock" // tests point it elsewhere

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		fmt.Println(usage())
		return
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, tr("error:"), err)
		if errors.Is(err, errChecksFailing) {
			os.Exit(2)
		}
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
	case "blueprint", "profiles": // profiles: name before 0.19
		return blueprint(args)
	case "certificates", "certs":
		return certificates(args)
	case "log":
		return logLines(args)
	case "sync":
		if _, err := call(agent.DesktopRequest{Op: "sync"}); err != nil {
			return err
		}
		fmt.Println(tr("sync requested"))
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
	case "support":
		if len(args) != 1 || args[0] != "end" {
			return errors.New(tr("usage: limdm support end"))
		}
		if _, err := call(agent.DesktopRequest{Op: "shell-end"}); err != nil {
			return err
		}
		fmt.Println(tr("remote support session ended"))
		return nil
	}
	return errors.New(tr("unknown command %q (limdm help)", cmd))
}

// call sends one request and reads one answer; errors of the agent come back
// as Go errors.
func call(req agent.DesktopRequest) (agent.DesktopResponse, error) {
	var resp agent.DesktopResponse
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "unix", socket)
	if err != nil {
		return resp, fmt.Errorf("%s (%w)", tr("the LiMDM agent does not answer; is it running?"), err)
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
			return resp, errors.New(tr("not allowed: only users signed in at this device, and root, may ask the agent"))
		}
		return resp, errors.New(tr(resp.Error))
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
		return tr("never")
	}
	return t.Local().Format("2006-01-02 15:04") + " (" + ago(*t) + ")"
}

func ago(t time.Time) string {
	d := time.Since(t).Round(time.Minute)
	switch {
	case d < time.Minute:
		return tr("just now")
	case d < time.Hour:
		return tr("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return tr("%d h ago", int(d.Hours()))
	}
	return trn(int(d.Hours()/24), "%d day ago", "%d days ago")
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
	row(w, tr("Managed by"), resp.Company)
	if st := resp.Status; st != nil {
		sys := st.System
		fmt.Fprintf(w, "%s\t%s\n", tr("Hostname"), st.Hostname)
		row(w, tr("System"), strings.TrimSpace(sys.OS+" "+sys.Arch))
		row(w, tr("Kernel"), sys.Kernel)
		row(w, tr("Hardware"), strings.TrimSpace(sys.Vendor+" "+sys.Model))
		row(w, tr("Serial number"), sys.Serial)
		fmt.Fprintf(w, "\t\n")
		fmt.Fprintf(w, "%s\t%s\n", tr("Device ID"), st.DeviceID)
		fmt.Fprintf(w, "%s\t%s\n", tr("Server"), st.Server)
		fmt.Fprintf(w, "%s\t%s\n", tr("Agent"), st.Version)
		row(w, tr("Inventory"), sys.Inventory)
		fmt.Fprintf(w, "%s\t%s\n", tr("Last sync"), when(st.LastCheckin))
		if st.CheckinEvery > 0 {
			fmt.Fprintf(w, "%s\t%s\n", tr("Sync every"), tr("%s (and at once when IT sends a command)", time.Duration(st.CheckinEvery)*time.Second))
		}
		row(w, tr("Last error"), st.LastError)
		if st.QueuedEvents+st.QueuedResults > 0 {
			fmt.Fprintf(w, "%s\t%s, %s\n", tr("Waiting to send"), trn(st.QueuedEvents, "%d event", "%d events"),
				trn(st.QueuedResults, "%d command result", "%d command results"))
		}
		fmt.Fprintf(w, "%s\t%d (token %s)\n", tr("Declarations"), st.Declarations, st.DeclToken)
		row(w, tr("Updates"), st.Updates)
		if st.LastUpdateRun != nil {
			fmt.Fprintf(w, "%s\t%s\n", tr("Last update run"), when(st.LastUpdateRun))
		}
		fmt.Fprintf(w, "%s\t%s\n", tr("Desktop login"), st.DesktopLogin)
		fmt.Fprintf(w, "%s\t%s\n", tr("Remote scripts"), map[bool]string{true: tr("allowed"), false: tr("not allowed")}[st.ScriptsAllow])
		if st.RemoteShell != "" {
			fmt.Fprintf(w, "%s\t%s\n", tr("Remote support"), tr("session running: %s (end it: limdm support end)", st.RemoteShell))
		}
		if st.OfflineLockH > 0 {
			fmt.Fprintf(w, "%s\t%s\n", tr("Offline lock"), trn(st.OfflineLockH, "after %d hour without the server", "after %d hours without the server"))
		}
		switch {
		case st.LostMode:
			fmt.Fprintf(w, "%s\t%s\n", tr("Device lock"), tr("lost mode"))
		case st.OfflineLocked:
			fmt.Fprintf(w, "%s\t%s\n", tr("Device lock"), tr("locked: no server contact for too long"))
		case st.Locked:
			fmt.Fprintf(w, "%s\t%s\n", tr("Device lock"), tr("locked by IT"))
		}
		fmt.Fprintf(w, "\t\n")
		state := tr("compliant")
		if len(st.Failing) > 0 {
			state = trn(len(st.Failing), "%d of %d checks failing", "%d of %d checks failing", st.Checks)
		} else if st.Checks == 0 {
			state = tr("no compliance checks declared")
		}
		fmt.Fprintf(w, "%s\t%s\n", tr("Compliance"), state)
		for _, f := range st.Failing {
			fmt.Fprintf(w, "\t  %s %s\n", tr("failing:"), tr(f))
		}
		fmt.Fprintf(w, "%s\t%s\n", tr("Recovery keys"), trn(st.Escrowed, "%d escrowed", "%d escrowed"))
	}
	for _, v := range resp.Need {
		fmt.Fprintf(w, "%s\t%s\n", tr("Action needed"), tr("recovery key for %s (run: limdm recovery-key)", v.Device))
	}
	fmt.Fprintf(w, "%s\t%s\n", tr("Blueprint"), trn(len(resp.Profiles), "%d setting in force (limdm blueprint)", "%d settings in force (limdm blueprint)"))
	fmt.Fprintf(w, "%s\t%s\n", tr("Certificates"), trn(len(resp.Certs), "%d managed (limdm certificates)", "%d managed (limdm certificates)"))
	if s, err := call(agent.DesktopRequest{Op: "sso-status"}); err == nil && s.SSO != nil && s.SSO.Managed {
		fmt.Fprintf(w, "%s\t%s\n", tr("Company account"), ssoLine(s.SSO))
	}
	return w.Flush()
}

// row prints a line only when there is a value.
func row(w io.Writer, label, value string) {
	if value != "" {
		fmt.Fprintf(w, "%s\t%s\n", label, value)
	}
}

// errChecksFailing makes limdm checks --strict exit with 2.
var errChecksFailing = errors.New(tr("compliance checks failing"))

// sortChecks puts failing checks first, then exceptions, not applicable and
// passed ones, each by level and ID.
func sortChecks(list []agent.DesktopCheck) {
	rank := map[string]int{"fail": 0, "excepted": 1, "na": 2, "pass": 3}
	slices.SortStableFunc(list, func(a, b agent.DesktopCheck) int {
		ra, oka := rank[a.Status]
		rb, okb := rank[b.Status]
		if !oka {
			ra = 4
		}
		if !okb {
			rb = 4
		}
		if ra != rb {
			return ra - rb
		}
		if a.Level != b.Level {
			return a.Level - b.Level
		}
		return strings.Compare(a.ID, b.ID)
	})
}

func checks(args []string) error {
	rest, asJSON := jsonFlag(args)
	strict := slices.Contains(rest, "--strict") || slices.Contains(rest, "-strict")
	resp, err := call(agent.DesktopRequest{Op: "info"})
	if err != nil {
		return err
	}
	var list []agent.DesktopCheck
	if resp.Status != nil {
		list = resp.Status.CheckList
	}
	sortChecks(list)
	failing := slices.ContainsFunc(list, func(c agent.DesktopCheck) bool { return c.Status == "fail" })
	if asJSON {
		err = printJSON(list)
	} else if len(list) == 0 {
		fmt.Println(tr("no compliance checks declared for this device"))
	} else {
		w := table()
		fmt.Fprintln(w, tr("STATUS\tLEVEL\tID\tCHECK\tDETAIL"))
		for _, c := range list {
			level := "-"
			if c.Level > 0 {
				level = fmt.Sprint(c.Level)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", strings.ToUpper(c.Status), level, c.ID, tr(c.Title), c.Detail)
		}
		err = w.Flush()
	}
	if err == nil && strict && failing {
		return errChecksFailing
	}
	return err
}

func blueprint(args []string) error {
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
	fmt.Fprintln(w, tr("STATE\tTYPE\tIDENTIFIER"))
	for _, p := range resp.Profiles {
		state := tr("active")
		if !p.Active {
			state = tr("not achieved")
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
		fmt.Println(tr("no managed certificates"))
		return nil
	}
	w := table()
	fmt.Fprintln(w, tr("NAME\tSUBJECT\tVALID UNTIL\tSHA-256"))
	for _, c := range resp.Certs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.Name, c.Subject, c.NotAfter.Local().Format("2006-01-02"), c.SHA256)
	}
	return w.Flush()
}

func logLines(args []string) error {
	rest, asJSON := jsonFlag(args)
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	n := fs.Int("n", 50, tr("number of entries"))
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
	note := fs.String("note", "", tr("a note for IT"))
	remote := fs.String("remote", "", tr("Flatpak remote of the app (request-new)"))
	name := fs.String("name", "", tr("display name (request-new)"))
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
			return errors.New(tr("usage: limdm software %s APP", sub))
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
			fmt.Println(tr("request sent to IT; it shows up in limdm software list once decided"))
		case "install":
			fmt.Println(tr("installation of %s started; follow it with: limdm software list", id))
		default:
			fmt.Println(tr("removal of %s started; follow it with: limdm software list", id))
		}
		return nil
	case "search":
		if len(pos) == 0 {
			return errors.New(tr("usage: limdm software search QUERY"))
		}
		resp, err := call(agent.DesktopRequest{Op: "search", Query: strings.Join(pos, " ")})
		if err != nil {
			return err
		}
		if asJSON {
			return printJSON(resp.Hits)
		}
		if len(resp.Hits) == 0 {
			fmt.Println(tr("nothing found, or everything found is in the catalog already (limdm software list)"))
			return nil
		}
		w := table()
		fmt.Fprintln(w, tr("FLATPAK ID\tNAME\tSUMMARY"))
		for _, h := range resp.Hits {
			fmt.Fprintf(w, "%s\t%s\t%s\n", h.ID, h.Name, h.Summary)
		}
		fmt.Fprintln(w, "\n"+tr("ask IT for one: limdm software request-new FLATPAK_ID --note \"why\""))
		return w.Flush()
	case "request-new":
		if len(pos) != 1 {
			return errors.New(tr("usage: limdm software request-new FLATPAK_ID [--remote flathub] [--name NAME] [--note TEXT]"))
		}
		if _, err := call(agent.DesktopRequest{Op: "app-request-new", Flatpak: pos[0], Remote: *remote, Name: *name, Note: *note}); err != nil {
			return err
		}
		fmt.Println(tr("request sent to IT; follow it with: limdm software requests"))
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
			fmt.Println(tr("no requests for apps outside the catalog"))
			return nil
		}
		w := table()
		fmt.Fprintln(w, tr("STATUS\tFLATPAK ID\tNAME"))
		for _, r := range resp.Requests {
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Status, r.Flatpak, r.Name)
		}
		return w.Flush()
	}
	return errors.New(tr("unknown software command %q (limdm help)", sub))
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
		fmt.Println(tr("the company catalog is empty for this device"))
		return nil
	}
	w := table()
	fmt.Fprintln(w, tr("APP\tNAME\tSTATE\tAVAILABILITY"))
	for _, a := range resp.Apps {
		state := tr("not installed")
		switch {
		case a.Busy == "install":
			state = tr("installation running")
		case a.Busy != "":
			state = tr("removal running")
		case a.Error != "":
			state = tr("failed:") + " " + tr(a.Error)
		case a.Installed:
			state = tr("installed")
			if a.Via != "" {
				state += " (" + a.Via + ")"
			}
		}
		avail := map[string]string{"available": tr("install yourself"), "request": tr("on request"), "required": tr("required by IT")}[a.Mode]
		if avail == "" {
			avail = a.Mode
		}
		if r := map[string]string{"pending": tr("request pending"), "approved": tr("request approved"), "denied": tr("request declined")}[a.Request]; r != "" {
			avail += ", " + r
		} else if a.Request != "" {
			avail += ", " + a.Request
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.ID, a.Name, state, avail)
	}
	if s := resp.Store; s != nil && s.ReadOnly {
		fmt.Fprintln(w, "\n"+tr("software centers are read only on this device: install through this catalog"))
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
		return "", errors.New(tr("%q is not in the catalog (limdm software list, or limdm software search)", q))
	}
	return "", errors.New(tr("%q matches several apps: %s", q, strings.Join(hits, ", ")))
}

// ---- company account and recovery key ----

func ssoLine(s *agent.SSOStatus) string {
	switch {
	case s.Running:
		return tr("confirmation running")
	case s.Due:
		return s.Email + ": " + tr("confirmation due (limdm sso confirm)")
	case s.Confirmed != nil:
		line := s.Email + ": " + tr("confirmed %s", ago(*s.Confirmed))
		if s.Deadline != nil {
			line += ", " + tr("next by %s", s.Deadline.Local().Format("2006-01-02"))
		}
		return line
	}
	return s.Email + ": " + tr("not confirmed yet (limdm sso confirm)")
}

func sso(sub string) error {
	switch sub {
	case "status":
		resp, err := call(agent.DesktopRequest{Op: "sso-status"})
		if err != nil {
			return err
		}
		if resp.SSO == nil || !resp.SSO.Managed {
			fmt.Println(tr("your account is not managed by the company directory on this device"))
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
			return errors.New(tr("your account is not managed by the company directory on this device"))
		}
		fmt.Println(tr("Open %s and enter the code %s", resp.SSO.URI, resp.SSO.Code))
		fmt.Println(tr("waiting for the sign in (Ctrl+C stops waiting, the sign in stays valid) …"))
		for range 120 { // ten minutes, the lifetime of the device code
			time.Sleep(5 * time.Second)
			st, err := call(agent.DesktopRequest{Op: "sso-status"})
			if err != nil {
				return err
			}
			if s := st.SSO; s != nil && !s.Running {
				if s.Error != "" {
					return errors.New(tr(s.Error))
				}
				fmt.Println(tr("confirmed"))
				return nil
			}
		}
		return errors.New(tr("no sign in within ten minutes"))
	}
	return errors.New(tr("unknown sso command %q (status or confirm)", sub))
}

func recoveryKey() error {
	resp, err := call(agent.DesktopRequest{Op: "status"})
	if err != nil {
		return err
	}
	if len(resp.Need) == 0 {
		fmt.Println(tr("no recovery key is needed on this device"))
		return nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New(tr("the passphrase is read from a terminal only"))
	}
	for _, v := range resp.Need {
		fmt.Fprint(os.Stderr, tr("Disk passphrase of %s: ", v.Device))
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		if _, err := call(agent.DesktopRequest{Op: "escrow", UUID: v.UUID, Passphrase: string(pw)}); err != nil {
			return fmt.Errorf("%s: %w", v.Device, err)
		}
		fmt.Println(tr("recovery key for %s created; it reaches IT with the next sync", v.Device))
	}
	return nil
}
