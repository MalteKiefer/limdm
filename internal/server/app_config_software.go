package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// API of the software catalog and the package repository for the console
// app (/app/config?tab=software, ?tab=packages). Every change runs through
// the functions of the classic pages (software.go, packages.go) with their
// role, four eyes and audit rules. The catalog serves every tenant and is
// managed globally, like its console pages; packages belong to a tenant.

func (s *Server) appConfigSoftwareRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/software/catalog", s.need("audit", s.softwareAPI(s.apiCatalog)))
	m.HandleFunc("POST /api/v1/software/apps", s.need("admin", s.softwareAPI(s.apiCatalogAppSave)))
	m.HandleFunc("PUT /api/v1/software/apps/{id}", s.need("admin", s.softwareAPI(s.apiCatalogAppSave)))
	m.HandleFunc("DELETE /api/v1/software/apps/{id}", s.need("admin", s.softwareAPI(s.apiCatalogAppDelete)))
	m.HandleFunc("POST /api/v1/software/import", s.need("admin", s.softwareAPI(s.apiCatalogImport)))
	m.HandleFunc("GET /api/v1/software/flathub/search", s.need("audit", s.softwareAPI(func(w http.ResponseWriter, r *http.Request, _ apiCaller) { s.flathubSearchJSON(w, r) })))
	m.HandleFunc("POST /api/v1/software/flathub", s.need("admin", s.softwareAPI(s.apiFlathubAdd)))
	m.HandleFunc("GET /api/v1/software/requests", s.need("audit", s.softwareAPI(s.apiAppRequests)))
	m.HandleFunc("POST /api/v1/software/requests/{id}/{op}", s.need("admin", s.softwareAPI(s.apiAppRequestDecide)))
	m.HandleFunc("GET /api/v1/software/remotes", s.need("audit", s.softwareAPI(s.apiRemotes)))
	m.HandleFunc("PUT /api/v1/software/remotes/{name}", s.need("admin", s.softwareAPI(s.apiRemoteSave)))
	m.HandleFunc("POST /api/v1/software/remotes/{name}/{op}", s.need("admin", s.softwareAPI(s.apiRemoteOp)))
	m.HandleFunc("GET /api/v1/software/settings", s.need("audit", s.softwareAPI(s.apiSoftwareSettings)))
	m.HandleFunc("PUT /api/v1/software/settings", s.need("admin", s.softwareAPI(s.apiSoftwareSettingsSave)))
	m.HandleFunc("GET /api/v1/packages", s.need("audit", unscopedAPI(s.apiPackages)))
	m.HandleFunc("POST /api/v1/packages", s.need("admin", unscopedAPI(s.apiPackageUpload)))
	m.HandleFunc("DELETE /api/v1/packages/{id}", s.need("admin", unscopedAPI(s.apiPackageDelete)))
	m.HandleFunc("PUT /api/v1/packages/settings", s.need("admin", unscopedAPI(s.apiPackageSettings)))
}

// softwareAPI refuses accounts bound to a tenant and device scoped ones, as
// the console's software pages do (not tenant routes, unscoped).
func (s *Server) softwareAPI(h apiHandlerFunc) apiHandlerFunc {
	return unscopedAPI(func(w http.ResponseWriter, r *http.Request, c apiCaller) {
		if c.sess().TenantOnly() {
			problem(w, http.StatusForbidden, "the software catalog is managed by global administrators")
			return
		}
		h(w, r, c)
	})
}

// deviceScoped reports an account or token limited to some devices: the
// console's scope rule (scoped), and also an admin token that carries scope
// tags. Such callers never change fleet wide configuration.
func deviceScoped(sess session) bool {
	return sess.scoped() || len(sess.Tags) > 0 || len(sess.Groups) > 0
}

// unscopedAPI refuses device scoped callers before the handler reads the
// request body, as the console's unscoped wrapper does for its pages.
func unscopedAPI(h apiHandlerFunc) apiHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, c apiCaller) {
		if deviceScoped(c.sess()) {
			problem(w, http.StatusForbidden, "not available for accounts limited to a device scope")
			return
		}
		h(w, r, c)
	}
}

// apiBodyLimit is the request size the admin API accepts: a package upload
// gets the upload limit and more time, every other request 1 MiB.
func (s *Server) apiBodyLimit(w http.ResponseWriter, r *http.Request) int64 {
	if r.Method != http.MethodPost || r.URL.Path != "/api/v1/packages" {
		return 1 << 20
	}
	c, err := s.packageConfig(r.Context())
	if err != nil {
		return 1 << 20
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(time.Hour))
	_ = rc.SetWriteDeadline(time.Now().Add(time.Hour))
	return int64(c.MaxUploadMB)<<20 + 1<<20
}

// ---- catalog ----

type apiCatalogApp struct {
	api.CatalogApp
	Enabled  bool      `json:"enabled"`
	Scope    []int64   `json:"scope"`
	HasIcon  bool      `json:"has_icon"`
	Updated  time.Time `json:"updated_at"`
	Installs int       `json:"installs"`
}

type apiFleetFlatpak struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Origin  string `json:"origin"`
	Devices int    `json:"devices"`
}

func (s *Server) apiCatalog(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	apps, err := s.catalogApps(ctx, s.db, "")
	if err != nil {
		s.apiFail(w, err)
		return
	}
	counts := map[string]int{}
	rows, err := s.db.Query(ctx, `SELECT a->>'id', count(*)::int FROM devices d, jsonb_array_elements(coalesce(d.inventory->'apps', '[]'::jsonb)) a
		WHERE NOT d.retired AND (a->>'installed')::boolean GROUP BY 1`)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			rows.Close()
			s.apiFail(w, err)
			return
		}
		counts[id] = n
	}
	rows.Close()
	out := []apiCatalogApp{}
	for _, a := range apps {
		a.Signature, a.Seq = "", 0
		if a.Sources == nil {
			a.Sources = []api.AppSource{}
		}
		out = append(out, apiCatalogApp{a.CatalogApp, a.Enabled, nonNilIDs(a.Scope), a.HasIcon, a.Updated, counts[a.ID]})
	}
	fleet, err := s.fleetFlatpaks(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	found := []apiFleetFlatpak{}
	for _, f := range fleet {
		found = append(found, apiFleetFlatpak(f))
	}
	var pending int
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM catalog_requests WHERE status='pending'`).Scan(&pending)
	writeJSON(w, map[string]any{"items": out, "fleet": found, "pending_requests": pending})
}

func nonNilIDs(v []int64) []int64 {
	if v == nil {
		return []int64{}
	}
	return v
}

// apiCatalogAppInput is a catalog app as the console form edits it.
type apiCatalogAppInput struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Summary    string          `json:"summary"`
	Category   string          `json:"category"`
	Mode       string          `json:"mode"`
	Sources    []api.AppSource `json:"sources"`
	Detect     []string        `json:"detect"`
	Enabled    bool            `json:"enabled"`
	Scope      []int64         `json:"scope"`
	Icon       []byte          `json:"icon,omitempty"` // PNG, base64
	RemoveIcon bool            `json:"remove_icon"`
}

func (s *Server) apiCatalogAppSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var in apiCatalogAppInput
	if !decodeJSON(w, r, &in) {
		return
	}
	isNew := r.Method == http.MethodPost
	if !isNew {
		in.ID = r.PathValue("id")
	}
	if in.Icon != nil {
		if err := validLogo(in.Icon); err != nil {
			s.apiFail(w, invalid("icon", errors.New(strings.Replace(err.Error(), "logo", "icon", 1))))
			return
		}
	}
	app := catalogRow{CatalogApp: api.CatalogApp{ID: strings.TrimSpace(in.ID), Name: strings.TrimSpace(in.Name), Summary: strings.TrimSpace(in.Summary),
		Category: strings.TrimSpace(in.Category), Mode: in.Mode, Sources: in.Sources, Detect: in.Detect}, Enabled: in.Enabled, Scope: in.Scope}
	for i, src := range app.Sources { // as the console form: a vendor key ends with a newline
		for j, rp := range src.Repos {
			if k := strings.TrimSpace(rp.Key); k != "" {
				app.Sources[i].Repos[j].Key = k + "\n"
			}
		}
	}
	pending, err := s.saveCatalogApp(r.Context(), c.sess(), app, isNew, in.Icon, in.RemoveIcon)
	switch {
	case errors.Is(err, errAppExists) && isNew:
		problem(w, http.StatusConflict, "An app with this ID exists already.")
	case errors.Is(err, errAppExists):
		problem(w, http.StatusNotFound, "Unknown app.")
	case err != nil:
		s.apiFail(w, err)
	case pending:
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"status": "pending"})
	default:
		writeJSON(w, map[string]any{"id": app.ID, "status": "saved"})
	}
}

func (s *Server) apiCatalogAppDelete(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if err := s.deleteCatalogApp(r.Context(), c.actor(), r.PathValue("id")); err != nil {
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiCatalogImport(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var in struct {
		Flatpaks []string `json:"flatpaks"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	added, err := s.importFleetFlatpaks(r.Context(), c.actor(), in.Flatpaks)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"added": nonNil(added)})
}

func (s *Server) apiFlathubAdd(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var in struct {
		ID   string `json:"id"`
		Mode string `json:"mode"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	in.ID = strings.TrimSpace(in.ID)
	if !api.ValidFlatpakID(in.ID) {
		s.apiFail(w, invalid("id", errors.New("not a Flatpak application ID")))
		return
	}
	slug, pending, err := s.addFlathubApp(r.Context(), c.sess(), in.ID, in.Mode)
	switch {
	case errors.Is(err, errAppExists):
		problem(w, http.StatusConflict, "The catalog has this app already.")
	case err != nil:
		s.apiFail(w, err)
	case pending:
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"id": slug, "status": "pending"})
	default:
		writeJSONStatus(w, http.StatusCreated, map[string]any{"id": slug, "status": "saved"})
	}
}

// ---- requests ----

type apiAppRequest struct {
	ID        int64      `json:"id"`
	DeviceID  string     `json:"device_id"`
	Hostname  string     `json:"hostname"`
	App       string     `json:"app"`
	AppName   string     `json:"app_name"`
	User      string     `json:"user"`
	Note      string     `json:"note"`
	Status    string     `json:"status"`
	DecidedBy *string    `json:"decided_by"`
	CreatedAt time.Time  `json:"created_at"`
	DecidedAt *time.Time `json:"decided_at"`
	Flatpak   string     `json:"flatpak"`
	Remote    string     `json:"remote"`
	Install   bool       `json:"install"`       // approved with install by the agent
	State     string     `json:"install_state"` // installed | install_failed, or empty
	Error     string     `json:"install_error"`
}

func (s *Server) apiAppRequests(w http.ResponseWriter, r *http.Request, c apiCaller) {
	rows, err := s.db.Query(r.Context(), `SELECT q.id, q.device_id, d.hostname, coalesce(q.app, ''), coalesce(a.name, q.app_name), q.username, q.note, q.status,
		q.decided_by, q.created_at, q.decided_at, q.flatpak, q.remote, q.install AND q.status='approved', q.install_state, q.install_error
		FROM catalog_requests q JOIN devices d ON d.id=q.device_id LEFT JOIN catalog_apps a ON a.slug=q.app
		ORDER BY (q.status='pending') DESC, q.created_at DESC LIMIT 300`)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[apiAppRequest])
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if list == nil {
		list = []apiAppRequest{}
	}
	writeJSON(w, listPage{Items: list})
}

func (s *Server) apiAppRequestDecide(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Install bool `json:"install"` // approve: the agent installs the app at once
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &in) {
		return
	}
	err := s.decideAppRequest(r.Context(), c.actor(), id, r.PathValue("op"), in.Install)
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, http.StatusNotFound, "no pending request with this ID")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"id": id, "status": "decided"})
}

// ---- remotes and settings ----

type apiRemote struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Title       string `json:"title"`
	State       string `json:"state"`
	CatalogOnly bool   `json:"catalog_only"`
	Devices     int    `json:"devices"`
	Managed     bool   `json:"managed"`
}

func (s *Server) apiRemotes(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	managed, err := s.catalogRemotes(ctx, s.db)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	counts := map[string]int{}
	rows, err := s.db.Query(ctx, `SELECT r->>'name', count(DISTINCT d.id)::int FROM devices d, jsonb_array_elements(coalesce(d.inventory->'flatpak_remotes', '[]'::jsonb)) r
		WHERE NOT d.retired AND NOT coalesce((r->>'disabled')::boolean, false) GROUP BY 1`)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	for rows.Next() {
		var n string
		var k int
		if err := rows.Scan(&n, &k); err != nil {
			rows.Close()
			s.apiFail(w, err)
			return
		}
		counts[n] = k
	}
	rows.Close()
	out := []apiRemote{}
	for _, m := range managed {
		out = append(out, apiRemote{m.Name, m.URL, m.Title, m.State, m.CatalogOnly, counts[m.Name], true})
	}
	rows, err = s.db.Query(ctx, `SELECT r->>'name', max(r->>'url'), max(coalesce(r->>'title', '')), count(DISTINCT d.id)::int
		FROM devices d, jsonb_array_elements(coalesce(d.inventory->'flatpak_remotes', '[]'::jsonb)) r
		WHERE NOT d.retired AND NOT EXISTS (SELECT 1 FROM catalog_remotes c WHERE c.name = r->>'name')
		GROUP BY 1 ORDER BY 4 DESC, 1`)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	found, err := pgx.CollectRows(rows, pgx.RowToStructByPos[foundRemote])
	if err != nil {
		s.apiFail(w, err)
		return
	}
	for _, f := range found {
		out = append(out, apiRemote{Name: f.Name, URL: f.URL, Title: f.Title, Devices: f.Devices})
	}
	writeJSON(w, listPage{Items: out})
}

func (s *Server) apiRemoteSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var in apiRemote
	if !decodeJSON(w, r, &in) {
		return
	}
	rem := api.CatalogRemote{Name: r.PathValue("name"), URL: strings.TrimSpace(in.URL), Title: truncate(strings.TrimSpace(in.Title), 80),
		State: firstNonEmpty(in.State, "allowed"), CatalogOnly: in.CatalogOnly}
	if err := s.saveCatalogRemote(r.Context(), c.actor(), rem); err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"name": rem.Name, "status": "saved"})
}

func (s *Server) apiRemoteOp(w http.ResponseWriter, r *http.Request, c apiCaller) {
	err := s.catalogRemoteOp(r.Context(), c.actor(), r.PathValue("name"), r.PathValue("op"))
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, http.StatusNotFound, "remote not found")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"name": r.PathValue("name"), "status": "saved"})
}

func (s *Server) apiSoftwareSettings(w http.ResponseWriter, r *http.Request, c apiCaller) {
	set, err := s.softwareSettings(r.Context(), s.db)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, set)
}

func (s *Server) apiSoftwareSettingsSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var set SoftwareSettings
	if !decodeJSON(w, r, &set) {
		return
	}
	if err := s.saveSoftwareSettings(r.Context(), c.actor(), set); err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, set)
}

// ---- packages ----

type apiPackage struct {
	ID         int64     `json:"id"`
	Tenant     int64     `json:"tenant_id"`
	SHA256     string    `json:"sha256"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	Kind       string    `json:"kind"`
	Filename   string    `json:"filename"`
	Store      string    `json:"store"`
	Size       int64     `json:"size"`
	UploadedBy string    `json:"uploaded_by"`
	ApprovedBy *string   `json:"approved_by"`
	CreatedAt  time.Time `json:"created_at"`
	Usage      []string  `json:"usage"`   // library items that install it
	Snippet    string    `json:"snippet"` // payload of a library item that installs it
}

// apiPackageS3 is the S3 store without its sealed secrets; a save keeps the
// stored secret unless secret is set.
type apiPackageS3 struct {
	Endpoint  string `json:"endpoint"`
	Region    string `json:"region"`
	Bucket    string `json:"bucket"`
	Prefix    string `json:"prefix"`
	AccessKey string `json:"access_key"`
	PathStyle bool   `json:"path_style"`
	Secret    string `json:"secret,omitempty"`
}

type apiPackageConfig struct {
	MaxUploadMB int           `json:"max_upload_mb"`
	QuotaMB     int           `json:"quota_mb"`
	QuotaCount  int           `json:"quota_count"`
	Store       string        `json:"store"` // local or s3
	S3          *apiPackageS3 `json:"s3,omitempty"`
}

func (s *Server) apiPackages(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx, sess := r.Context(), c.sess()
	tcond, targs := tenantCond(sess, "a.tenant_id", 0)
	icond, _ := tenantCond(sess, "i.tenant_id", 0)
	rows, err := s.db.Query(ctx, `SELECT a.id, a.tenant_id, a.sha256, a.name, a.version, a.kind, a.filename, a.store, a.size, a.uploaded_by, a.approved_by, a.created_at,
		coalesce((SELECT array_agg(i.name ORDER BY i.name) FROM library_items i WHERE i.type = '`+api.TypeArtifacts+`' AND `+icond+`
			AND i.payload->'artifacts' @> jsonb_build_array(jsonb_build_object('sha256', a.sha256))), '{}')
		FROM artifacts a WHERE `+tcond+` ORDER BY a.name, a.created_at DESC`, targs...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[artifactRow])
	if err != nil {
		s.apiFail(w, err)
		return
	}
	cfg, err := s.packageConfig(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out := []apiPackage{}
	var used, count int64
	for _, a := range list {
		if a.Tenant == ownerTenant(ctx) {
			used += a.Size
			count++
		}
		out = append(out, apiPackage{a.ID, a.Tenant, a.SHA256, a.Name, a.Version, a.Kind, a.Filename, a.Store, a.Size, a.UploadedBy, a.ApprovedBy,
			a.CreatedAt, nonNil(a.Usage), a.Snippet()})
	}
	conf := apiPackageConfig{MaxUploadMB: cfg.MaxUploadMB, QuotaMB: cfg.QuotaMB, QuotaCount: cfg.QuotaCount, Store: "local"}
	if cfg.S3 != nil {
		conf.Store = "s3"
		conf.S3 = &apiPackageS3{Endpoint: cfg.S3.Endpoint, Region: cfg.S3.Region, Bucket: cfg.S3.Bucket, Prefix: cfg.S3.Prefix, AccessKey: cfg.S3.AccessKey, PathStyle: cfg.S3.PathStyle}
	}
	writeJSON(w, map[string]any{"items": out, "config": conf, "used_bytes": used, "used_count": count, "kinds": api.ArtifactKinds,
		"four_eyes": s.settings().FourEyes, "global": !sess.TenantOnly(), "type": api.TypeArtifacts})
}

// apiPackageUpload takes a multipart form as the console page does: name,
// version, kind, reason and file.
func (s *Server) apiPackageUpload(w http.ResponseWriter, r *http.Request, c apiCaller) {
	f, hdr, err := r.FormFile("file")
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			problem(w, http.StatusRequestEntityTooLarge, "the file is larger than the upload limit")
			return
		}
		s.apiFail(w, invalid("file", errors.New("choose a file (at most the upload limit)")))
		return
	}
	defer f.Close()
	pending, err := s.storeUpload(r.Context(), c.sess(), r.FormValue("name"), r.FormValue("version"), r.FormValue("kind"), hdr.Filename, f, r.FormValue("reason"))
	if err != nil {
		s.apiFail(w, err)
		return
	}
	status := "uploaded"
	if pending {
		status = "pending"
	}
	writeJSONStatus(w, http.StatusCreated, map[string]any{"status": status})
}

func (s *Server) apiPackageDelete(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.deletePackage(r.Context(), c.sess(), id); err != nil {
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// apiPackageSettings saves the limits and the store through the console's
// target logic (target seals the S3 secret, keeps the stored one).
func (s *Server) apiPackageSettings(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if !backupAdmin(c.sess()) {
		problem(w, http.StatusForbidden, "the package store is managed by global administrators")
		return
	}
	var in apiPackageConfig
	if !decodeJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	cur, err := s.packageConfig(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	next := cur
	next.MaxUploadMB, next.QuotaMB, next.QuotaCount, next.S3 = in.MaxUploadMB, in.QuotaMB, in.QuotaCount, nil
	if in.Store == "s3" {
		if in.S3 == nil {
			s.apiFail(w, invalid("s3", errors.New("the S3 store needs endpoint, bucket and access key")))
			return
		}
		t, err := s.target(targetInput{StoreTarget: StoreTarget{Name: "packages", Kind: "s3", Endpoint: in.S3.Endpoint, Region: in.S3.Region,
			Bucket: in.S3.Bucket, Prefix: in.S3.Prefix, AccessKey: in.S3.AccessKey, PathStyle: in.S3.PathStyle}, Secret: in.S3.Secret}, cur.S3)
		if err != nil {
			s.apiFail(w, err)
			return
		}
		next.S3 = &t
	}
	if err := s.savePackageConfig(ctx, c.actor(), cur, next); err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"status": "saved", "max_upload_mb": next.MaxUploadMB, "quota_mb": next.QuotaMB, "quota_count": next.QuotaCount,
		"store": map[bool]string{true: "s3", false: "local"}[next.S3 != nil]})
}
