package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Patch management (docs/patching.md): update rings and waves, the update
// gate a device gets at its check in, the pending update list and last
// runs the agent reports, and the fleet view of open security updates and
// CVEs.
//
// The ring model: rings are ordered per tenant. An admin (or the schedule
// of the first ring, wave_days) starts a wave; the first ring has it at
// once. Ring N gets the newest wave that is at least its deferral_days old
// and that ring N-1 already has, unless ring N-1 or ring N is paused, and,
// with require_approval, only once an admin approved it. A device in a
// ring installs the sources whose rule follows rings once per wave that
// reached its ring; a paused ring installs nothing.

const ringLoopPeriod = 5 * time.Minute

func init() {
	for a, l := range map[string]string{"update_ring.save": "Update ring saved", "update_ring.delete": "Update ring deleted",
		"update_ring.pause": "Update ring paused", "update_ring.resume": "Update ring resumed", "update_ring.approve": "Update ring approved",
		"update_wave.start": "Update wave started", "update_ring.wave": "Update wave reached ring", "cve_feeds.refresh": "CVE data import started"} {
		auditActions[a] = l
	}
}

func (s *Server) appPatchRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/update-rings", s.need("read", s.apiUpdateRings))
	m.HandleFunc("POST /api/v1/update-rings", s.need("admin", s.apiUpdateRingSave))
	m.HandleFunc("PUT /api/v1/update-rings/{id}", s.need("admin", s.apiUpdateRingSave))
	m.HandleFunc("DELETE /api/v1/update-rings/{id}", s.need("admin", s.apiUpdateRingDelete))
	m.HandleFunc("POST /api/v1/update-rings/{id}/{action}", s.need("admin", s.apiUpdateRingAction))
	m.HandleFunc("POST /api/v1/update-waves", s.need("admin", s.apiUpdateWaveStart))
	m.HandleFunc("GET /api/v1/devices/{id}/updates", s.need("read", s.apiDeviceUpdates))
	m.HandleFunc("GET /api/v1/updates/fleet", s.need("read", s.apiUpdatesFleet))
	m.HandleFunc("GET /api/v1/updates/package-versions", s.need("read", s.apiPackageVersions))
	m.HandleFunc("GET /api/v1/updates/cve-feeds", s.need("read", s.apiCVEFeeds))
	m.HandleFunc("POST /api/v1/updates/cve-feeds/refresh", s.need("admin", s.apiCVEFeedsRefresh))
}

type updateRing struct {
	ID              int64      `json:"id"`
	Tenant          int64      `json:"tenant_id"`
	Name            string     `json:"name"`
	Position        int        `json:"position"`
	DeferralDays    int        `json:"deferral_days"`
	WaveDays        int        `json:"wave_days"`
	Paused          bool       `json:"paused"`
	RequireApproval bool       `json:"require_approval"`
	ApprovedWave    int        `json:"approved_wave"`
	AllDevices      bool       `json:"all_devices"`
	Tags            []string   `json:"tags"`
	Groups          []string   `json:"groups"`
	Blueprints      []int64    `json:"blueprints"`
	Wave            int        `json:"wave"`
	WaveAt          *time.Time `json:"wave_at"`
	Devices         int        `json:"devices"`
}

const ringCols = `r.id, r.tenant_id, r.name, r.position, r.deferral_days, r.wave_days, r.paused, r.require_approval, r.approved_wave,
	r.all_devices, r.tags, r.groups, r.blueprints, r.wave, r.wave_at`

type updateWave struct {
	Tenant    int64     `json:"tenant_id"`
	Wave      int       `json:"wave"`
	StartedAt time.Time `json:"started_at"`
	StartedBy string    `json:"started_by"`
}

// ringTenant is the tenant new rings and waves belong to.
func ringTenant(sess session) int64 {
	if sess.Tenant == 0 {
		return defaultTenant
	}
	return sess.Tenant
}

// matches reports whether a device with these tags, directory groups and
// blueprint chain belongs to the ring.
func (r updateRing) matches(tags, groups []string, blueprints []int64) bool {
	return r.AllDevices || slices.ContainsFunc(r.Tags, func(t string) bool { return slices.Contains(tags, t) }) ||
		slices.ContainsFunc(r.Groups, func(g string) bool { return slices.Contains(groups, g) }) ||
		slices.ContainsFunc(r.Blueprints, func(b int64) bool { return slices.Contains(blueprints, b) })
}

// ringOf is the first ring (by position) a device belongs to, or nil.
func ringOf(rings []updateRing, tags, groups []string, blueprints []int64) *updateRing {
	for i := range rings {
		if rings[i].matches(tags, groups, blueprints) {
			return &rings[i]
		}
	}
	return nil
}

// advanceRings moves waves along the rings of one tenant (ordered by
// position) and returns the indexes of the rings that got a new wave.
// waves are the tenant's waves, oldest first.
func advanceRings(rings []updateRing, waves []updateWave, now time.Time) []int {
	var changed []int
	for i := range rings {
		r := &rings[i]
		target := 0
		if i == 0 {
			if len(waves) > 0 {
				target = waves[len(waves)-1].Wave
			}
		} else {
			prev := rings[i-1]
			if prev.Paused {
				continue
			}
			for _, w := range waves {
				if w.Wave <= prev.Wave && !w.StartedAt.After(now.Add(-time.Duration(r.DeferralDays)*24*time.Hour)) {
					target = w.Wave
				}
			}
			if r.RequireApproval {
				target = min(target, r.ApprovedWave)
			}
		}
		if r.Paused || target <= r.Wave {
			continue
		}
		t := now
		r.Wave, r.WaveAt = target, &t
		changed = append(changed, i)
	}
	return changed
}

// waveDue reports whether the first ring's schedule starts a new wave.
func waveDue(first updateRing, waves []updateWave, now time.Time) bool {
	if first.WaveDays <= 0 || first.Paused {
		return false
	}
	return len(waves) == 0 || now.Sub(waves[len(waves)-1].StartedAt) >= time.Duration(first.WaveDays)*24*time.Hour
}

func loadRings(ctx context.Context, q querier, tenant int64, lock bool) ([]updateRing, error) {
	sql := `SELECT ` + ringCols + `, 0 FROM update_rings r WHERE r.tenant_id=$1 ORDER BY r.position, r.id`
	if lock {
		sql += ` FOR UPDATE`
	}
	rows, err := q.Query(ctx, sql, tenant)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[updateRing])
}

func loadWaves(ctx context.Context, q querier, tenant int64) ([]updateWave, error) {
	rows, err := q.Query(ctx, `SELECT tenant_id, wave, started_at, started_by FROM update_waves WHERE tenant_id=$1 ORDER BY wave`, tenant)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[updateWave])
}

// advanceTenant starts a scheduled wave and moves waves along the rings
// of one tenant, audited as the system.
func (s *Server) advanceTenant(ctx context.Context, tenant int64) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rings, err := loadRings(ctx, tx, tenant, true)
	if err != nil || len(rings) == 0 {
		return err
	}
	waves, err := loadWaves(ctx, tx, tenant)
	if err != nil {
		return err
	}
	now := time.Now()
	if waveDue(rings[0], waves, now) {
		w, err := startWave(ctx, tx, tenant, "system")
		if err != nil {
			return err
		}
		waves = append(waves, w)
	}
	for _, i := range advanceRings(rings, waves, now) {
		r := rings[i]
		if _, err := tx.Exec(ctx, `UPDATE update_rings SET wave=$2, wave_at=$3 WHERE id=$1`, r.ID, r.Wave, r.WaveAt); err != nil {
			return err
		}
		if err := audit(ctx, tx, "system", "update_ring.wave", r.Name, fmt.Sprintf("wave %d reached ring %s", r.Wave, r.Name)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func startWave(ctx context.Context, tx pgx.Tx, tenant int64, actor string) (updateWave, error) {
	w := updateWave{Tenant: tenant, StartedBy: actor}
	err := tx.QueryRow(ctx, `INSERT INTO update_waves(tenant_id, wave, started_by)
		SELECT $1, coalesce(max(wave), 0) + 1, $2 FROM update_waves WHERE tenant_id=$1 RETURNING wave, started_at`, tenant, actor).Scan(&w.Wave, &w.StartedAt)
	if err != nil {
		return w, err
	}
	return w, audit(ctx, tx, actor, "update_wave.start", fmt.Sprintf("wave %d", w.Wave), "")
}

// advanceAll runs advanceTenant for every tenant with rings.
func (s *Server) advanceAll(ctx context.Context) error {
	tenants, err := collect(ctx, s.db, pgx.RowTo[int64], `SELECT DISTINCT tenant_id FROM update_rings`)
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range tenants {
		errs = append(errs, s.advanceTenant(ctx, t))
	}
	return errors.Join(errs...)
}

func (s *Server) ringLoop(ctx context.Context) {
	t := time.NewTicker(ringLoopPeriod)
	defer t.Stop()
	for {
		if err := s.advanceAll(ctx); err != nil {
			s.log.Error("update rings", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// updateGate finds the device's ring at its check in, remembers it on the
// device and returns the gate the agent follows (nil: in no ring).
func updateGate(ctx context.Context, tx pgx.Tx, id string, chain []blueprintRec) (*api.UpdateGate, error) {
	var tenant int64
	var tags []string
	var cur *int64
	if err := tx.QueryRow(ctx, `SELECT tenant_id, tags, update_ring_id FROM devices WHERE id=$1`, id).Scan(&tenant, &tags, &cur); err != nil {
		return nil, err
	}
	rings, err := loadRings(ctx, tx, tenant, false)
	if err != nil || len(rings) == 0 && cur == nil {
		return nil, err
	}
	groups, _, err := directoryFacts(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	bps := make([]int64, len(chain))
	for i, b := range chain {
		bps[i] = b.ID
	}
	r := ringOf(rings, tags, groups, bps)
	var rid *int64
	if r != nil {
		rid = &r.ID
	}
	if (rid == nil) != (cur == nil) || rid != nil && *rid != *cur {
		if _, err := tx.Exec(ctx, `UPDATE devices SET update_ring_id=$2 WHERE id=$1`, id, rid); err != nil {
			return nil, err
		}
	}
	if r == nil {
		return nil, nil
	}
	return &api.UpdateGate{Ring: r.Name, Wave: r.Wave, Open: !r.Paused}, nil
}

// storeUpdateStatus keeps the patch part of a status report, bounded: it
// comes from the device.
func storeUpdateStatus(ctx context.Context, tx pgx.Tx, id string, st *api.UpdateStatus) error {
	if st != nil {
		if len(st.Pending) > 1000 {
			st.Pending = st.Pending[:1000]
		}
		for i := range st.Pending {
			p := &st.Pending[i]
			p.Name, p.Current, p.Candidate, p.Origin = truncate(p.Name, 200), truncate(p.Current, 200), truncate(p.Candidate, 200), truncate(p.Origin, 200)
			p.Source, p.Severity = truncate(p.Source, 20), truncate(p.Severity, 20)
			if len(p.CVEs) > 50 {
				p.CVEs = p.CVEs[:50]
			}
			p.CVEs = slices.DeleteFunc(p.CVEs, func(c string) bool { return !cveRe.MatchString(c) })
		}
		if len(st.Runs) > len(api.UpdateSources) {
			st.Runs = st.Runs[:len(api.UpdateSources)]
		}
		for i := range st.Runs {
			st.Runs[i].Detail = truncate(st.Runs[i].Detail, 500)
		}
		st.PendingError, st.Ring = truncate(st.PendingError, 300), truncate(st.Ring, 64)
	}
	_, err := tx.Exec(ctx, `UPDATE devices SET updates=$2 WHERE id=$1`, id, jsonb(st))
	return err
}

var cveRe = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)

// ---- endpoints ----

func (s *Server) apiUpdateRings(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	cond, args := tenantCond(c.sess(), "r.tenant_id", 0)
	scope, sargs := scopeCond(c.sess(), len(args))
	list, err := collect(ctx, s.db, pgx.RowToStructByPos[updateRing], `SELECT `+ringCols+`,
			(SELECT count(*) FROM devices d WHERE d.update_ring_id = r.id AND NOT d.retired AND `+scope+`)::int
		FROM update_rings r WHERE `+cond+` ORDER BY r.tenant_id, r.position, r.id`, append(args, sargs...)...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	wcond, wargs := tenantCond(c.sess(), "tenant_id", 0)
	waves, err := collect(ctx, s.db, pgx.RowToStructByPos[updateWave], `SELECT tenant_id, wave, started_at, started_by FROM update_waves
		WHERE `+wcond+` ORDER BY started_at DESC LIMIT 20`, wargs...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	var none int
	scope0, args0 := scopeCond(c.sess(), 0)
	if err := s.db.QueryRow(ctx, `SELECT count(*)::int FROM devices d WHERE d.update_ring_id IS NULL AND NOT d.retired AND `+scope0, args0...).Scan(&none); err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"items": nonNilSlice(list), "waves": nonNilSlice(waves), "unassigned": none})
}

type ringInput struct {
	Name            string   `json:"name"`
	Position        int      `json:"position"`
	DeferralDays    int      `json:"deferral_days"`
	WaveDays        int      `json:"wave_days"`
	RequireApproval bool     `json:"require_approval"`
	AllDevices      bool     `json:"all_devices"`
	Tags            []string `json:"tags"`
	Groups          []string `json:"groups"`
	Blueprints      []int64  `json:"blueprints"`
}

var ringNameRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,63}$`)

// validate returns the field and message of the first problem.
func (in *ringInput) validate() (string, string) {
	in.Name = strings.TrimSpace(in.Name)
	switch {
	case !ringNameRe.MatchString(in.Name):
		return "name", "name: 1 to 64 letters, digits, space, dot, dash, underscore"
	case in.Position < 1 || in.Position > 100:
		return "position", "position: 1 to 100"
	case in.DeferralDays < 0 || in.DeferralDays > 90:
		return "deferral_days", "deferral_days: 0 to 90"
	case in.WaveDays < 0 || in.WaveDays > 90:
		return "wave_days", "wave_days: 0 (manual) to 90"
	case len(in.Tags) > 50 || len(in.Groups) > 50 || len(in.Blueprints) > 50:
		return "tags", "at most 50 tags, groups and blueprints"
	}
	for i, t := range in.Tags { // as parseTags
		if t = strings.ToLower(strings.TrimSpace(t)); !identOK(t) || len(t) > 32 {
			return "tags", "tags: up to 32 letters, digits, dot, dash, underscore"
		}
		in.Tags[i] = t
	}
	for _, g := range in.Groups {
		if g = strings.TrimSpace(g); g == "" || len(g) > 200 {
			return "groups", "groups: directory group names"
		}
	}
	in.Tags, in.Groups, in.Blueprints = nonNilSlice(in.Tags), nonNilSlice(in.Groups), nonNilSlice(in.Blueprints)
	return "", ""
}

func (s *Server) apiUpdateRingSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var in ringInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if f, msg := in.validate(); f != "" {
		problemField(w, http.StatusUnprocessableEntity, f, msg)
		return
	}
	ctx := r.Context()
	sess := c.sess()
	tenant := ringTenant(sess)
	var id int64
	if r.PathValue("id") != "" {
		var ok bool
		if id, tenant, ok = s.ownRing(w, r, c); !ok {
			return
		}
	}
	for _, b := range in.Blueprints {
		var ok bool
		if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM blueprints WHERE id=$1 AND (tenant_id=$2 OR tenant_id=1 AND shared))`, b, tenant).Scan(&ok); err != nil {
			s.apiFail(w, err)
			return
		} else if !ok {
			problemField(w, http.StatusUnprocessableEntity, "blueprints", "blueprints: blueprints of the ring's tenant")
			return
		}
	}
	err := s.auditActionFn(ctx, func(tx pgx.Tx) (string, string, string, string, error) {
		var err error
		if id == 0 {
			err = tx.QueryRow(ctx, `INSERT INTO update_rings(tenant_id, name, position, deferral_days, wave_days, require_approval, all_devices, tags, groups, blueprints)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`, tenant, in.Name, in.Position, in.DeferralDays, in.WaveDays, in.RequireApproval,
				in.AllDevices, in.Tags, in.Groups, in.Blueprints).Scan(&id)
		} else {
			_, err = tx.Exec(ctx, `UPDATE update_rings SET name=$2, position=$3, deferral_days=$4, wave_days=$5, require_approval=$6, all_devices=$7,
				tags=$8, groups=$9, blueprints=$10 WHERE id=$1`, id, in.Name, in.Position, in.DeferralDays, in.WaveDays, in.RequireApproval,
				in.AllDevices, in.Tags, in.Groups, in.Blueprints)
		}
		return c.actor(), "update_ring.save", in.Name, fmt.Sprintf("#%d position=%d deferral=%d wave_days=%d approval=%v all=%v tags=%v groups=%v blueprints=%v",
			id, in.Position, in.DeferralDays, in.WaveDays, in.RequireApproval, in.AllDevices, in.Tags, in.Groups, in.Blueprints), err
	})
	var pe interface{ SQLState() string }
	if errors.As(err, &pe) && pe.SQLState() == "23505" {
		problemField(w, http.StatusUnprocessableEntity, "name", "name: a ring with this name exists")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	s.writeRing(w, r, id)
}

func (s *Server) writeRing(w http.ResponseWriter, r *http.Request, id int64) {
	ring, err := collectOne(r.Context(), s.db, pgx.RowToStructByPos[updateRing], `SELECT `+ringCols+`,
		(SELECT count(*) FROM devices d WHERE d.update_ring_id = r.id AND NOT d.retired)::int FROM update_rings r WHERE r.id=$1`, id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, ring)
}

// ownRing finds a ring of the caller's tenant.
func (s *Server) ownRing(w http.ResponseWriter, r *http.Request, c apiCaller) (int64, int64, bool) {
	id, ok := pathID(w, r)
	if !ok {
		return 0, 0, false
	}
	cond, args := tenantCond(c.sess(), "tenant_id", 1)
	var tenant int64
	err := s.db.QueryRow(r.Context(), `SELECT tenant_id FROM update_rings WHERE id=$1 AND `+cond, append([]any{id}, args...)...).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, http.StatusNotFound, "ring not found")
		return 0, 0, false
	}
	if err != nil {
		s.apiFail(w, err)
		return 0, 0, false
	}
	return id, tenant, true
}

func (s *Server) apiUpdateRingDelete(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, _, ok := s.ownRing(w, r, c)
	if !ok {
		return
	}
	ctx := r.Context()
	err := s.auditActionFn(ctx, func(tx pgx.Tx) (string, string, string, string, error) {
		var name string
		err := tx.QueryRow(ctx, `DELETE FROM update_rings WHERE id=$1 RETURNING name`, id).Scan(&name)
		return c.actor(), "update_ring.delete", name, fmt.Sprintf("#%d", id), err
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// apiUpdateRingAction pauses, resumes or approves a ring (approve: the
// wave the ring before it has may reach it).
func (s *Server) apiUpdateRingAction(w http.ResponseWriter, r *http.Request, c apiCaller) {
	action := r.PathValue("action")
	if !slices.Contains([]string{"pause", "resume", "approve"}, action) {
		problem(w, http.StatusNotFound, "unknown action")
		return
	}
	id, tenant, ok := s.ownRing(w, r, c)
	if !ok {
		return
	}
	ctx := r.Context()
	err := s.auditActionFn(ctx, func(tx pgx.Tx) (string, string, string, string, error) {
		var name string
		var err error
		switch action {
		case "approve":
			var wave int
			err = tx.QueryRow(ctx, `UPDATE update_rings r SET approved_wave = coalesce((SELECT p.wave FROM update_rings p
					WHERE p.tenant_id = r.tenant_id AND (p.position, p.id) < (r.position, r.id) ORDER BY p.position DESC, p.id DESC LIMIT 1), r.approved_wave)
				WHERE r.id=$1 RETURNING r.name, r.approved_wave`, id).Scan(&name, &wave)
			return c.actor(), "update_ring.approve", name, fmt.Sprintf("up to wave %d", wave), err
		default:
			err = tx.QueryRow(ctx, `UPDATE update_rings SET paused=$2 WHERE id=$1 RETURNING name`, id, action == "pause").Scan(&name)
			return c.actor(), "update_ring." + action, name, "", err
		}
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if err := s.advanceTenant(ctx, tenant); err != nil {
		s.apiFail(w, err)
		return
	}
	s.writeRing(w, r, id)
}

// apiUpdateWaveStart starts a new wave in the caller's tenant: the first
// ring installs the updates available then.
func (s *Server) apiUpdateWaveStart(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	tenant := ringTenant(c.sess())
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	defer tx.Rollback(ctx)
	rings, err := loadRings(ctx, tx, tenant, true)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if len(rings) == 0 {
		problem(w, http.StatusConflict, "create an update ring first")
		return
	}
	wave, err := startWave(ctx, tx, tenant, c.actor())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.apiFail(w, err)
		return
	}
	if err := s.advanceTenant(ctx, tenant); err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, wave)
}

type deviceCVE struct {
	CVE       string `json:"cve"`
	Package   string `json:"package"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed"`
	Severity  string `json:"severity"`
}

type deviceUpdates struct {
	Ring *updateRing `json:"ring"`
	// Vulnerabilities are the CVEs matched from the Debian and Ubuntu
	// security data (app_patch_cve.go).
	Vulnerabilities []deviceCVE      `json:"vulnerabilities"`
	Status          api.UpdateStatus `json:"status"`
	Reports         bool             `json:"reports"` // the agent sends an update status (older agents do not)
}

func (s *Server) apiDeviceUpdates(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id := r.PathValue("id")
	if _, ok := s.deviceFound(w, r, c, id); !ok {
		return
	}
	ctx := r.Context()
	var raw []byte
	var ring *int64
	if err := s.db.QueryRow(ctx, `SELECT updates, update_ring_id FROM devices WHERE id=$1`, id).Scan(&raw, &ring); err != nil {
		s.apiFail(w, err)
		return
	}
	var out deviceUpdates
	if raw != nil && string(raw) != "null" {
		if err := json.Unmarshal(raw, &out.Status); err != nil {
			s.apiFail(w, err)
			return
		}
		out.Reports = true
	}
	out.Status.Pending = nonNilSlice(out.Status.Pending)
	out.Status.Runs = nonNilSlice(out.Status.Runs)
	vulns, err := collect(ctx, s.db, pgx.RowToStructByPos[deviceCVE], `SELECT cve, package, installed, fixed, severity FROM device_cves WHERE device_id=$1
		ORDER BY CASE lower(severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, cve DESC, package LIMIT 2000`, id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out.Vulnerabilities = nonNilSlice(vulns)
	annotatePending(out.Status.Pending, vulns)
	if ring != nil {
		rg, err := collectOne(ctx, s.db, pgx.RowToStructByPos[updateRing], `SELECT `+ringCols+`, 0 FROM update_rings r WHERE r.id=$1`, *ring)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			s.apiFail(w, err)
			return
		}
		if err == nil {
			out.Ring = &rg
		}
	}
	writeJSON(w, out)
}

type fleetCVE struct {
	ID         string   `json:"id"`
	Severity   string   `json:"severity"`
	Devices    int      `json:"devices"`
	Packages   []string `json:"packages"`
	severities []string
}

type fleetPackage struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	Security   bool   `json:"security"`
	Severity   string `json:"severity"`
	Devices    int    `json:"devices"`
	severities []string
}

type fleetDevice struct {
	ID       string   `json:"id"`
	Hostname string   `json:"hostname"`
	Packages []string `json:"packages"`
}

// maxSeverity is the highest of the advisory severities.
func maxSeverity(list []string) string {
	best := ""
	for _, s := range list {
		if severityRank(s) > severityRank(best) {
			best = s
		}
	}
	return best
}

// severityRank orders the severities of Red Hat, Fedora and SUSE
// advisories, Debian urgencies and Ubuntu priorities.
func severityRank(s string) int {
	return map[string]int{"low": 1, "moderate": 2, "medium": 2, "important": 3, "high": 3, "critical": 4}[strings.ToLower(s)]
}

// annotatePending adds the CVEs matched from the Debian and Ubuntu data to
// the pending updates of the same package (apt reports none itself).
func annotatePending(pending []api.PendingUpdate, vulns []deviceCVE) {
	for i := range pending {
		p := &pending[i]
		for _, v := range vulns {
			if v.Package == p.Name && !slices.Contains(p.CVEs, v.CVE) && len(p.CVEs) < 50 {
				p.CVEs = append(p.CVEs, v.CVE)
				if severityRank(v.Severity) > severityRank(p.Severity) {
					p.Severity = v.Severity
				}
			}
		}
	}
}

// apiUpdatesFleet summarises the pending updates the devices in scope
// report: devices with security updates, open CVEs (with a fix
// available) and packages. ?cve= lists the devices one CVE affects.
func (s *Server) apiUpdatesFleet(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	scope, args := scopeCond(c.sess(), 0)
	pending := `FROM devices d CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(d.updates->'pending') = 'array' THEN d.updates->'pending' ELSE '[]' END) p
		WHERE NOT d.retired AND ` + scope
	if cve := r.URL.Query().Get("cve"); cve != "" {
		if !cveRe.MatchString(cve) {
			problemField(w, http.StatusBadRequest, "cve", "cve: CVE-YYYY-NNNN")
			return
		}
		n := fmt.Sprint(len(args) + 1)
		list, err := collect(ctx, s.db, pgx.RowToStructByPos[fleetDevice], `SELECT x.id, x.hostname, array_agg(DISTINCT x.pkg ORDER BY x.pkg) FROM (
				SELECT d.id, d.hostname, p->>'name' AS pkg `+pending+` AND p->'cves' ? $`+n+`
				UNION ALL SELECT d.id, d.hostname, c.package FROM device_cves c JOIN devices d ON d.id = c.device_id WHERE c.cve = $`+n+` AND NOT d.retired AND `+scope+`
			) x GROUP BY x.id, x.hostname ORDER BY x.hostname LIMIT 500`, append(args, cve)...)
		if err != nil {
			s.apiFail(w, err)
			return
		}
		writeJSON(w, listPage{Items: nonNilSlice(list)})
		return
	}
	var st struct {
		Reporting int            `json:"reporting"`         // devices that send an update status
		Security  int            `json:"security_devices"`  // with pending security updates
		Pending   int            `json:"pending_devices"`   // with any pending update
		CVEs      []fleetCVE     `json:"cves"`              // open CVEs with a fix available, most devices first
		Packages  []fleetPackage `json:"packages"`          // pending updates, security first
		NoCVEData int            `json:"security_no_cve"`   // security updates without CVE IDs (apt)
		Sources   map[string]int `json:"devices_by_source"` // devices with pending updates per source
	}
	err := s.db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE d.updates IS NOT NULL AND d.updates <> 'null')::int,
			count(*) FILTER (WHERE EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(d.updates->'pending') = 'array' THEN d.updates->'pending' ELSE '[]' END) p WHERE (p->>'security')::bool))::int,
			count(*) FILTER (WHERE jsonb_array_length(CASE WHEN jsonb_typeof(d.updates->'pending') = 'array' THEN d.updates->'pending' ELSE '[]' END) > 0)::int
		FROM devices d WHERE NOT d.retired AND `+scope, args...).Scan(&st.Reporting, &st.Security, &st.Pending)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	// CVEs of pending updates (dnf, zypper) and matched from the Debian and Ubuntu data
	rows, err := s.db.Query(ctx, `SELECT x.cve, count(DISTINCT x.dev)::int, array_agg(DISTINCT x.pkg), array_agg(DISTINCT x.sev) FROM (
			SELECT cve, d.id AS dev, p->>'name' AS pkg, coalesce(p->>'severity', '') AS sev
			`+strings.Replace(pending, "WHERE", "CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(p->'cves') = 'array' THEN p->'cves' ELSE '[]' END) cve WHERE", 1)+`
			UNION ALL SELECT c.cve, d.id, c.package, c.severity FROM device_cves c JOIN devices d ON d.id = c.device_id WHERE NOT d.retired AND `+scope+`
		) x GROUP BY x.cve ORDER BY 2 DESC, 1 DESC LIMIT 500`, args...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	st.CVEs, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (fleetCVE, error) {
		var f fleetCVE
		err := row.Scan(&f.ID, &f.Devices, &f.Packages, &f.severities)
		f.Severity = maxSeverity(f.severities)
		return f, err
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	rows, err = s.db.Query(ctx, `SELECT p->>'name', min(coalesce(p->>'source', '')), coalesce(bool_or((p->>'security')::bool), false),
			array_agg(DISTINCT coalesce(p->>'severity', '')), count(DISTINCT d.id)::int `+pending+`
		GROUP BY 1 ORDER BY 3 DESC, 5 DESC, 1 LIMIT 300`, args...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	st.Packages, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (fleetPackage, error) {
		var f fleetPackage
		err := row.Scan(&f.Name, &f.Source, &f.Security, &f.severities, &f.Devices)
		f.Severity = maxSeverity(f.severities)
		return f, err
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	st.Sources = map[string]int{}
	type srcCount struct {
		Source string
		N      int
	}
	counts, err := collect(ctx, s.db, pgx.RowToStructByPos[srcCount], `SELECT coalesce(p->>'source', ''), count(DISTINCT d.id)::int `+pending+` GROUP BY 1`, args...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	for _, sc := range counts {
		st.Sources[sc.Source] = sc.N
	}
	if err := s.db.QueryRow(ctx, `SELECT count(*)::int `+pending+` AND (p->>'security')::bool AND jsonb_array_length(coalesce(p->'cves', '[]')) = 0
		AND NOT EXISTS (SELECT 1 FROM device_cves c WHERE c.device_id = d.id AND c.package = p->>'name')`, args...).Scan(&st.NoCVEData); err != nil {
		s.apiFail(w, err)
		return
	}
	st.CVEs, st.Packages = nonNilSlice(st.CVEs), nonNilSlice(st.Packages)
	writeJSON(w, st)
}

// apiPackageVersions lists the installed versions of one package across
// the devices in scope.
func (s *Server) apiPackageVersions(w http.ResponseWriter, r *http.Request, c apiCaller) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" || len(name) > 200 {
		problemField(w, http.StatusBadRequest, "name", "name: a package name")
		return
	}
	scope, args := scopeCond(c.sess(), 1)
	type version struct {
		Version string `json:"version"`
		Arch    string `json:"arch"`
		Devices int    `json:"devices"`
	}
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[version], `SELECT p.version, p.arch, count(DISTINCT d.id)::int
		FROM device_packages p JOIN devices d ON d.id = p.device_id WHERE p.name = $1 AND NOT d.retired AND `+scope+`
		GROUP BY 1, 2 ORDER BY 3 DESC, 1 DESC LIMIT 200`, append([]any{name}, args...)...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, listPage{Items: nonNilSlice(list)})
}

// packageCommandPayload builds the payload of package_hold and
// package_downgrade from the console form (name, version, release).
func packageCommandPayload(r *http.Request, typ string) ([]byte, error) {
	name := strings.TrimSpace(r.FormValue("name"))
	if typ == "package_hold" {
		p := api.PackageHold{Name: name, Release: r.FormValue("release") == "on" || r.FormValue("release") == "1"}
		if err := p.Validate(); err != nil {
			return nil, err
		}
		return json.Marshal(p)
	}
	p := api.PackageDowngrade{Name: name, Version: strings.TrimSpace(r.FormValue("version"))}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}
