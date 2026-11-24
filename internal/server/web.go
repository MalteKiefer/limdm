package server

import (
	"bytes"
	"context"
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

//go:embed web/*.html web/static
var webFS embed.FS

var staticFS, _ = fs.Sub(webFS, "web")

var pages = func() map[string]*template.Template {
	funcs := template.FuncMap{
		"ago": func(t *time.Time) string {
			if t == nil {
				return "never"
			}
			return time.Since(*t).Round(time.Second).String()
		},
		"join":    strings.Join,
		"fmtTime": func(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05") },
	}
	m := map[string]*template.Template{}
	names, _ := fs.Glob(webFS, "web/*.html")
	for _, n := range names {
		if n == "web/layout.html" {
			continue
		}
		key := strings.TrimSuffix(strings.TrimPrefix(n, "web/"), ".html")
		m[key] = template.Must(template.New("layout.html").Funcs(funcs).ParseFS(webFS, "web/layout.html", n))
	}
	return m
}()

type handler func(w http.ResponseWriter, r *http.Request, sess session)

// page enforces login, admin role for every state change, and CSRF.
func (s *Server) page(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.session(w, r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if sess.Role != "admin" {
				http.Error(w, "read only role", http.StatusForbidden)
				return
			}
			if !s.csrfOK(r, sess) {
				http.Error(w, "csrf check failed", http.StatusForbidden)
				return
			}
		}
		h(w, r, sess)
	}
}

func (s *Server) render(w http.ResponseWriter, sess session, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Sess"] = sess
	data["CSRF"] = s.csrfToken(sess)
	data["Page"] = name
	var buf bytes.Buffer
	if err := pages[name].Execute(&buf, data); err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

func (s *Server) webRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.page(s.devices))
	mux.HandleFunc("GET /devices/{id}", s.page(s.device))
	mux.HandleFunc("POST /devices/{id}/command", s.page(s.deviceCommand))
	mux.HandleFunc("POST /devices/{id}/assign", s.page(s.deviceAssign))
	mux.HandleFunc("POST /devices/{id}/retire", s.page(s.deviceRetire))
	mux.HandleFunc("GET /blueprints", s.page(s.blueprints))
	mux.HandleFunc("GET /blueprints/{id}", s.page(s.blueprintEdit))
	mux.HandleFunc("POST /blueprints", s.page(s.blueprintSave))
	mux.HandleFunc("GET /tokens", s.page(s.tokens))
	mux.HandleFunc("POST /tokens", s.page(s.tokenCreate))
	mux.HandleFunc("GET /compliance", s.page(s.compliance))
	mux.HandleFunc("GET /audit", s.page(s.auditPage))
	mux.HandleFunc("GET /export/{kind}", s.page(s.export))
}

// ---- devices ----

type deviceRow struct {
	ID, Hostname, OS, AgentVersion, Blueprints string
	Failing                                    int
	Checks                                     int
	LastSeen                                   *time.Time
	Retired                                    bool
	Status, Class                              string
}

func (s *Server) status(d *deviceRow) {
	switch {
	case d.Retired:
		d.Status, d.Class = "retired", "na"
	case d.LastSeen == nil || d.Checks == 0:
		d.Status, d.Class = "pending", "warn"
	case time.Since(*d.LastSeen) > s.cfg.StaleAfter:
		d.Status, d.Class = "stale", "warn"
	case d.Failing > 0:
		d.Status, d.Class = "non-compliant", "bad"
	default:
		d.Status, d.Class = "compliant", "ok"
	}
}

func (s *Server) listDevices(ctx context.Context) ([]deviceRow, error) {
	rows, err := s.db.Query(ctx, `SELECT d.id, d.hostname, coalesce(d.inventory->>'os_name',''), d.agent_version,
		coalesce((SELECT string_agg(b.name, ', ' ORDER BY b.priority) FROM device_blueprints db JOIN blueprints b ON b.id=db.blueprint_id WHERE db.device_id=d.id),''),
		d.failing, jsonb_array_length(d.checks), d.last_seen, d.retired
		FROM devices d ORDER BY d.retired, d.hostname`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (deviceRow, error) {
		var d deviceRow
		err := row.Scan(&d.ID, &d.Hostname, &d.OS, &d.AgentVersion, &d.Blueprints, &d.Failing, &d.Checks, &d.LastSeen, &d.Retired)
		s.status(&d)
		return d, err
	})
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request, sess session) {
	list, err := s.listDevices(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, sess, "devices", map[string]any{"Devices": list})
}

type blueprintRow struct {
	ID       int64
	Name     string
	Priority int
	Updated  time.Time
	Devices  int
	Assigned bool
}

func (s *Server) blueprintList(ctx context.Context, deviceID string) ([]blueprintRow, error) {
	rows, err := s.db.Query(ctx, `SELECT b.id, b.name, b.priority, b.updated_at,
		(SELECT count(*) FROM device_blueprints db JOIN devices d ON d.id=db.device_id WHERE db.blueprint_id=b.id AND NOT d.retired),
		EXISTS(SELECT 1 FROM device_blueprints db WHERE db.blueprint_id=b.id AND db.device_id=$1)
		FROM blueprints b ORDER BY b.priority, b.name`, deviceID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[blueprintRow])
}

func (s *Server) device(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	id := r.PathValue("id")
	var d deviceRow
	var inv, checks, decl, users, pkgs []byte
	var enrolled, certExp time.Time
	err := s.db.QueryRow(ctx, `SELECT id, hostname, agent_version, failing, jsonb_array_length(checks), last_seen, retired,
		inventory, checks, decl_status, users, packages, enrolled_at, cert_not_after FROM devices WHERE id=$1`, id).
		Scan(&d.ID, &d.Hostname, &d.AgentVersion, &d.Failing, &d.Checks, &d.LastSeen, &d.Retired, &inv, &checks, &decl, &users, &pkgs, &enrolled, &certExp)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.status(&d)
	var data struct {
		Inv      api.Inventory
		Checks   []api.CheckResult
		Decl     []api.DeclarationStatus
		Users    []api.User
		Packages []api.Package
	}
	if err := errors.Join(json.Unmarshal(inv, &data.Inv), json.Unmarshal(checks, &data.Checks), json.Unmarshal(decl, &data.Decl),
		json.Unmarshal(users, &data.Users), json.Unmarshal(pkgs, &data.Packages)); err != nil {
		s.fail(w, err)
		return
	}
	sort.SliceStable(data.Checks, func(i, j int) bool { return data.Checks[i].Status == "fail" && data.Checks[j].Status != "fail" })
	var userLines []string
	for _, u := range data.Users {
		l := u.Username + " " + u.Email
		if u.Admin {
			l += " admin"
		}
		userLines = append(userLines, l)
	}
	rows, err := s.db.Query(ctx, `SELECT id, type, status, output, created_by, created_at FROM commands WHERE device_id=$1 ORDER BY id DESC LIMIT 50`, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	type cmd struct {
		ID                       int64
		Type, Status, Output, By string
		At                       time.Time
	}
	cmds, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (cmd, error) {
		var c cmd
		return c, row.Scan(&c.ID, &c.Type, &c.Status, &c.Output, &c.By, &c.At)
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	bps, err := s.blueprintList(ctx, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	// expected declarations, to show what the device has not confirmed yet
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer tx.Rollback(ctx)
	want, err := effectiveDeclarations(ctx, tx, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	type declRow struct {
		Identifier, Type, State, Class string
		Reasons                        []string
	}
	reported := map[string]api.DeclarationStatus{}
	for _, st := range data.Decl {
		reported[st.Identifier] = st
	}
	var declRows []declRow
	for _, dcl := range want {
		row := declRow{Identifier: dcl.Identifier, Type: dcl.Type}
		st, ok := reported[dcl.Identifier]
		switch {
		case !ok || st.ServerToken != dcl.ServerToken:
			row.State, row.Class = "pending", "warn"
		case !st.Valid:
			row.State, row.Class, row.Reasons = "invalid", "bad", st.Reasons
		case !st.Active:
			row.State, row.Class, row.Reasons = "not achieved", "bad", st.Reasons
		default:
			row.State, row.Class = "active", "ok"
		}
		declRows = append(declRows, row)
	}
	s.render(w, sess, "device", map[string]any{
		"D": d, "Inv": data.Inv, "Checks": data.Checks, "Decl": declRows, "Users": strings.Join(userLines, "\n"),
		"PackageCount": len(data.Packages), "Commands": cmds, "Blueprints": bps, "Enrolled": enrolled, "CertExp": certExp,
	})
}

func (s *Server) deviceCommand(w http.ResponseWriter, r *http.Request, sess session) {
	id, typ, payload := r.PathValue("id"), r.FormValue("type"), r.FormValue("payload")
	if !slices.Contains([]string{"sync", "update", "reboot", "script"}, typ) || len(payload) > 64<<10 {
		http.Error(w, "invalid command", http.StatusBadRequest)
		return
	}
	if typ != "script" {
		payload = ""
	}
	err := s.auditAction(r.Context(), sess.Email, "command."+typ, id, truncate(payload, 2000), func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `INSERT INTO commands(device_id, type, payload, created_by) VALUES ($1,$2,$3,$4)`, id, typ, payload, sess.Email)
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/devices/"+id, http.StatusSeeOther)
}

func parseUsers(text string) ([]api.User, error) {
	users := []api.User{}
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 2 || len(f) > 3 || (len(f) == 3 && f[2] != "admin") {
			return nil, fmt.Errorf("line %q: expected 'username email [admin]'", line)
		}
		u := api.User{Username: f[0], Email: strings.ToLower(f[1]), Admin: len(f) == 3}
		if err := u.Validate(); err != nil {
			return nil, err
		}
		if seen[u.Username] {
			return nil, fmt.Errorf("user %s listed twice", u.Username)
		}
		seen[u.Username] = true
		users = append(users, u)
	}
	return users, nil
}

func (s *Server) deviceAssign(w http.ResponseWriter, r *http.Request, sess session) {
	id := r.PathValue("id")
	users, err := parseUsers(r.FormValue("users"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var bpIDs []int64
	for _, v := range r.Form["blueprint"] {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			http.Error(w, "invalid blueprint", http.StatusBadRequest)
			return
		}
		bpIDs = append(bpIDs, n)
	}
	ub, _ := json.Marshal(users)
	err = s.auditAction(r.Context(), sess.Email, "device.assign", id, fmt.Sprintf("blueprints=%v users=%s", bpIDs, ub), func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `UPDATE devices SET users=$2 WHERE id=$1`, id, string(ub)); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM device_blueprints WHERE device_id=$1`, id); err != nil {
			return err
		}
		_, err := tx.Exec(r.Context(), `INSERT INTO device_blueprints(device_id, blueprint_id) SELECT $1, unnest($2::bigint[])`, id, bpIDs)
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/devices/"+id, http.StatusSeeOther)
}

func (s *Server) deviceRetire(w http.ResponseWriter, r *http.Request, sess session) {
	id := r.PathValue("id")
	err := s.auditAction(r.Context(), sess.Email, "device.retire", id, "client certificate revoked", func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `UPDATE devices SET retired=true, cert_serial='' WHERE id=$1`, id)
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/devices/"+id, http.StatusSeeOther)
}

// ---- blueprints ----

func (s *Server) blueprints(w http.ResponseWriter, r *http.Request, sess session) {
	list, err := s.blueprintList(r.Context(), "")
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, sess, "blueprints", map[string]any{"Blueprints": list})
}

func (s *Server) blueprintEdit(w http.ResponseWriter, r *http.Request, sess session) {
	var id int64
	bp := api.Blueprint{Priority: 100, Declarations: []api.Declaration{}}
	if v := r.PathValue("id"); v != "new" {
		var raw []byte
		var err error
		id, err = strconv.ParseInt(v, 10, 64)
		if err == nil {
			err = s.db.QueryRow(r.Context(), `SELECT name, priority, declarations FROM blueprints WHERE id=$1`, id).Scan(&bp.Name, &bp.Priority, &raw)
		}
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if err := json.Unmarshal(raw, &bp.Declarations); err != nil {
			s.fail(w, err)
			return
		}
	}
	pretty, _ := json.MarshalIndent(bp.Declarations, "", "  ")
	s.renderBlueprint(w, sess, id, bp.Name, bp.Priority, string(pretty), "")
}

func (s *Server) renderBlueprint(w http.ResponseWriter, sess session, id int64, name string, prio int, doc, errMsg string) {
	types := make([]string, 0, len(api.Types))
	for t := range api.Types {
		types = append(types, t)
	}
	sort.Strings(types)
	var examples []map[string]string
	for _, t := range types {
		examples = append(examples, map[string]string{"Type": t, "Example": api.Types[t]})
	}
	s.render(w, sess, "blueprint", map[string]any{"ID": id, "Name": name, "Priority": prio, "Doc": doc, "Error": errMsg, "Types": examples})
}

func (s *Server) blueprintSave(w http.ResponseWriter, r *http.Request, sess session) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	prio, perr := strconv.Atoi(r.FormValue("priority"))
	bp := api.Blueprint{Name: strings.TrimSpace(r.FormValue("name")), Priority: prio}
	err := json.Unmarshal([]byte(r.FormValue("doc")), &bp.Declarations)
	if err == nil && perr != nil {
		err = errors.New("priority must be a number")
	}
	if err == nil {
		err = bp.Validate()
	}
	if err != nil {
		s.renderBlueprint(w, sess, id, bp.Name, prio, r.FormValue("doc"), err.Error())
		return
	}
	doc, _ := json.Marshal(bp.Declarations)
	err = s.auditAction(r.Context(), sess.Email, "blueprint.save", bp.Name, string(doc), func(tx pgx.Tx) error {
		if id > 0 {
			// The default blueprint applies to every device by name; it must keep it.
			tag, err := tx.Exec(r.Context(), `UPDATE blueprints SET name=$2, priority=$3, declarations=$4, updated_at=now()
				WHERE id=$1 AND (name <> 'default' OR $2 = 'default')`, id, bp.Name, bp.Priority, string(doc))
			if err == nil && tag.RowsAffected() == 0 {
				err = errors.New("blueprint not found, or default cannot be renamed")
			}
			return err
		}
		_, err := tx.Exec(r.Context(), `INSERT INTO blueprints(name, priority, declarations) VALUES ($1,$2,$3)`, bp.Name, bp.Priority, string(doc))
		return err
	})
	if err != nil {
		s.renderBlueprint(w, sess, id, bp.Name, prio, r.FormValue("doc"), err.Error())
		return
	}
	http.Redirect(w, r, "/blueprints", http.StatusSeeOther)
}

// ---- enrollment tokens ----

func (s *Server) tokens(w http.ResponseWriter, r *http.Request, sess session) {
	s.tokenPage(w, r, sess, "")
}

func (s *Server) tokenPage(w http.ResponseWriter, r *http.Request, sess session, created string) {
	type tok struct {
		Note, Blueprint, By string
		Uses                int
		Expires             time.Time
	}
	rows, err := s.db.Query(r.Context(), `SELECT t.note, coalesce(b.name,'default'), t.created_by, t.uses_left, t.expires_at
		FROM enroll_tokens t LEFT JOIN blueprints b ON b.id=t.blueprint_id WHERE t.expires_at > now() AND t.uses_left > 0 ORDER BY t.expires_at`)
	if err != nil {
		s.fail(w, err)
		return
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[tok])
	if err != nil {
		s.fail(w, err)
		return
	}
	bps, err := s.blueprintList(r.Context(), "")
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, sess, "tokens", map[string]any{"Tokens": list, "Blueprints": bps, "Created": created,
		"AgentURL": s.cfg.AgentURL, "Fingerprint": s.ca.Fingerprint()})
}

func (s *Server) tokenCreate(w http.ResponseWriter, r *http.Request, sess session) {
	uses, err1 := strconv.Atoi(r.FormValue("uses"))
	days, err2 := strconv.Atoi(r.FormValue("days"))
	if err1 != nil || err2 != nil || uses < 1 || uses > 10000 || days < 1 || days > 90 {
		http.Error(w, "uses 1..10000, days 1..90", http.StatusBadRequest)
		return
	}
	var bpID *int64
	if v, err := strconv.ParseInt(r.FormValue("blueprint_id"), 10, 64); err == nil && v > 0 {
		bpID = &v
	}
	token := "lmt_" + randToken(24)
	note := truncate(r.FormValue("note"), 200)
	err := s.auditAction(r.Context(), sess.Email, "token.create", note, fmt.Sprintf("uses=%d days=%d blueprint=%v", uses, days, r.FormValue("blueprint_id")), func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `INSERT INTO enroll_tokens(token_hash, note, blueprint_id, uses_left, expires_at, created_by)
			VALUES ($1,$2,$3,$4, now() + make_interval(days => $5), $6)`, sha(token), note, bpID, uses, days, sess.Email)
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.tokenPage(w, r, sess, token)
}

// ---- compliance reporting ----

type checkAgg struct {
	ID, Title                string
	Level                    int
	Refs                     api.Refs
	Pass, Fail, NA, Excepted int
	FailingHosts             []string
}

type controlAgg struct {
	Framework, Control string
	Checks             []string
	Pass, Fail         int
}

func (s *Server) compliance(w http.ResponseWriter, r *http.Request, sess session) {
	rows, err := s.db.Query(r.Context(), `SELECT hostname, checks, last_seen, failing FROM devices WHERE NOT retired`)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer rows.Close()
	checks := map[string]*checkAgg{}
	var total, compliant, stale, pending int
	for rows.Next() {
		var host string
		var raw []byte
		var seen *time.Time
		var failing int
		if err := rows.Scan(&host, &raw, &seen, &failing); err != nil {
			s.fail(w, err)
			return
		}
		total++
		switch {
		case seen == nil || len(raw) <= 2:
			pending++
		case time.Since(*seen) > s.cfg.StaleAfter:
			stale++
		case failing == 0:
			compliant++
		}
		var res []api.CheckResult
		if err := json.Unmarshal(raw, &res); err != nil {
			s.fail(w, err)
			return
		}
		for _, c := range res {
			a := checks[c.ID]
			if a == nil {
				a = &checkAgg{ID: c.ID, Title: c.Title, Level: c.Level, Refs: c.Refs}
				checks[c.ID] = a
			}
			switch c.Status {
			case "pass":
				a.Pass++
			case "fail":
				a.Fail++
				a.FailingHosts = append(a.FailingHosts, host)
			case "excepted":
				a.Excepted++
			default:
				a.NA++
			}
		}
	}
	if err := rows.Err(); err != nil {
		s.fail(w, err)
		return
	}
	var list []*checkAgg
	controls := map[string]*controlAgg{}
	for _, a := range checks {
		list = append(list, a)
		for fw, refs := range map[string][]string{"BSI IT-Grundschutz": a.Refs.BSI, "CIS Benchmark": a.Refs.CIS, "ISO/IEC 27001:2022": a.Refs.ISO} {
			for _, ref := range refs {
				k := fw + "|" + ref
				c := controls[k]
				if c == nil {
					c = &controlAgg{Framework: fw, Control: ref}
					controls[k] = c
				}
				c.Checks = append(c.Checks, a.ID)
				c.Pass += a.Pass
				c.Fail += a.Fail
			}
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	var ctl []*controlAgg
	for _, c := range controls {
		sort.Strings(c.Checks)
		ctl = append(ctl, c)
	}
	sort.Slice(ctl, func(i, j int) bool {
		if ctl[i].Framework != ctl[j].Framework {
			return ctl[i].Framework < ctl[j].Framework
		}
		return ctl[i].Control < ctl[j].Control
	})
	s.render(w, sess, "compliance", map[string]any{
		"Checks": list, "Controls": ctl, "Total": total, "Compliant": compliant, "Stale": stale,
		"NonCompliant": total - compliant - stale - pending, "Pending": pending, "StaleHours": int(s.cfg.StaleAfter.Hours()),
	})
}

// ---- audit ----

type auditRow struct {
	ID                            int64
	At                            time.Time
	Actor, Action, Target, Detail string
	Prev, Hash                    []byte
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request, sess session) {
	rows, err := s.db.Query(r.Context(), `SELECT id, at, actor, action, target, detail, prev, hash FROM audit_log ORDER BY id DESC LIMIT 300`)
	if err != nil {
		s.fail(w, err)
		return
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[auditRow])
	if err != nil {
		s.fail(w, err)
		return
	}
	brokenAt, err := s.verifyAudit(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, sess, "audit", map[string]any{"Entries": list, "BrokenAt": brokenAt})
}

// verifyAudit recomputes the hash chain. Returns the first broken id or 0.
// ponytail: full scan per page view; checkpoint verified ranges when the log reaches millions of rows.
func (s *Server) verifyAudit(ctx context.Context) (int64, error) {
	rows, err := s.db.Query(ctx, `SELECT id, at, actor, action, target, detail, prev, hash FROM audit_log ORDER BY id`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	prev := make([]byte, 32)
	for rows.Next() {
		var a auditRow
		if err := rows.Scan(&a.ID, &a.At, &a.Actor, &a.Action, &a.Target, &a.Detail, &a.Prev, &a.Hash); err != nil {
			return 0, err
		}
		if !bytes.Equal(a.Prev, prev) || !bytes.Equal(a.Hash, auditHash(a.Prev, a.At, a.Actor, a.Action, a.Target, a.Detail)) {
			return a.ID, nil
		}
		prev = a.Hash
	}
	return 0, rows.Err()
}

// ---- CSV exports (audit evidence) ----

// csvSafe neutralises spreadsheet formula injection from device supplied data.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func (s *Server) export(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	kind := r.PathValue("kind")
	var q string
	var header []string
	switch kind {
	case "compliance.csv":
		header = []string{"device_id", "hostname", "last_seen", "check_id", "level", "status", "detail", "bsi", "cis", "iso"}
		q = `SELECT d.id, d.hostname, coalesce(d.last_seen::text,''), c->>'id', coalesce(c->>'level',''), c->>'status', coalesce(c->>'detail',''),
			coalesce((SELECT string_agg(x,'; ') FROM jsonb_array_elements_text(c->'refs'->'bsi') x),''),
			coalesce((SELECT string_agg(x,'; ') FROM jsonb_array_elements_text(c->'refs'->'cis') x),''),
			coalesce((SELECT string_agg(x,'; ') FROM jsonb_array_elements_text(c->'refs'->'iso') x),'')
			FROM devices d, jsonb_array_elements(d.checks) c WHERE NOT d.retired ORDER BY d.hostname, c->>'id'`
	case "inventory.csv":
		header = []string{"device_id", "hostname", "os", "kernel", "agent", "serial", "vendor", "model", "cpu", "memory_mb", "disk_gb", "last_seen", "enrolled_at", "retired"}
		q = `SELECT id, hostname, coalesce(inventory->>'os_name',''), coalesce(inventory->>'kernel',''), agent_version,
			coalesce(inventory->>'serial',''), coalesce(inventory->>'vendor',''), coalesce(inventory->>'model',''), coalesce(inventory->>'cpu',''),
			coalesce(inventory->>'memory_mb',''), coalesce(inventory->>'disk_gb',''), coalesce(last_seen::text,''), enrolled_at::text, retired::text
			FROM devices ORDER BY hostname`
	case "audit.csv":
		header = []string{"id", "at", "actor", "action", "target", "detail", "hash"}
		q = `SELECT id::text, at::text, actor, action, target, detail, encode(hash,'hex') FROM audit_log ORDER BY id`
	default:
		http.NotFound(w, r)
		return
	}
	rows, err := s.db.Query(ctx, q)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer rows.Close()
	if err := s.auditAction(ctx, sess.Email, "export", kind, "", nil); err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="limdm-%s-%s"`, time.Now().Format("20060102"), kind))
	cw := csv.NewWriter(w)
	cw.Write(header)
	vals := make([]string, len(header))
	ptrs := make([]any, len(header))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			s.log.Error("export", "err", err)
			return
		}
		out := make([]string, len(vals))
		for i, v := range vals {
			out[i] = csvSafe(v)
		}
		cw.Write(out)
	}
	cw.Flush()
}
