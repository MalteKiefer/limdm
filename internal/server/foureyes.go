package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Four eyes approval for declarations that act like a script: with the
// setting on, saving or rolling back a library item of a root effective
// type, a catalog app that is required or adds a package repository, and an
// API token with the admin role become requests like a script command.
// What is approved is signed and written in the approver's transaction.

// rootTypes are the library item types that run code as root, change who
// is root, or decide what root trusts. com.limdm.files counts when a path
// needs allow_scripts on the device (api.SafeFilePath).
var rootTypes = map[string]bool{
	api.TypeScripts: true, api.TypeSudo: true, api.TypeLocalUsers: true, api.TypeRepositories: true,
	api.TypeLogin: true, api.TypeSSH: true, api.TypePolkit: true, api.TypeCertificates: true,
	api.TypeArtifacts: true, // installs uploaded packages as root
}

// itemNeedsApproval reports whether saving it needs a second admin.
func (s *Server) itemNeedsApproval(it api.LibraryItem) bool {
	if !s.settings().FourEyes {
		return false
	}
	if rootTypes[it.Type] {
		return true
	}
	if it.Type == api.TypeFirewall { // a remove list deletes rules on every device that gets the item
		var f api.Firewall
		return json.Unmarshal(it.Payload, &f) != nil || len(f.Remove) > 0
	}
	if it.Type != api.TypeFiles {
		return false
	}
	var p struct {
		Files []api.File `json:"files"`
	}
	if json.Unmarshal(it.Payload, &p) != nil {
		return true
	}
	for _, f := range p.Files {
		if !api.SafeFilePath(f.Path) {
			return true
		}
	}
	return false
}

// approvalPending is returned instead of saving: the change waits as request #n.
type approvalPending int64

func (p approvalPending) Error() string {
	return fmt.Sprintf("four eyes approval: request #%d waits for another administrator under Approvals", int64(p))
}

// pendingApproval reports the request ID when err is approvalPending.
func pendingApproval(err error) (int64, bool) {
	var p approvalPending
	if errors.As(err, &p) {
		return int64(p), true
	}
	return 0, false
}

// requester is the session a request is stored under for actor in ctx.
func requester(ctx context.Context, actor string) session {
	return session{Email: actor, Tenant: ctxTenant(ctx)}
}

// itemApproval is the payload of a library item request: the validated,
// sealed and compact item; the signature is made when it is approved.
type itemApproval struct {
	Item    api.LibraryItem `json:"item"`
	Action  string          `json:"action"` // library.save | library.rollback
	Note    string          `json:"note"`
	Restore bool            `json:"restore,omitempty"`
	Tenant  int64           `json:"tenant,omitempty"` // tenant the requester acted for, 0 global
}

func (s *Server) requestItemApproval(ctx context.Context, actor, action, note string, it api.LibraryItem, restore bool) error {
	id, err := s.requestApproval(ctx, requester(ctx, actor), "library.save", it.Name,
		itemApproval{Item: it, Action: action, Note: note, Restore: restore, Tenant: ctxTenant(ctx)}, "")
	if err != nil {
		return err
	}
	return approvalPending(id)
}

// applyItemApproval writes an approved item in the approver's transaction.
func applyItemApproval(ctx context.Context, tx pgx.Tx, a approval, approver string) error {
	var c itemApproval
	if err := json.Unmarshal(a.Payload, &c); err != nil {
		return err
	}
	if err := c.Item.Validate(); err != nil { // the request waited in the database
		return errApproval(err.Error())
	}
	ictx := withTenant(ctx, c.Tenant)
	note := c.Note + fmt.Sprintf(" (approval #%d by %s)", a.ID, approver)
	if err := writeItem(ictx, tx, a.RequestedBy, note, &c.Item, c.Restore); err != nil {
		var ue *userError
		if errors.As(err, &ue) || isUnique(err) {
			return errApproval(firstNonEmpty(errMessage(err), "the item cannot be saved"))
		}
		return err
	}
	return audit(ctx, tx, a.RequestedBy, c.Action, c.Item.Name, itemDetail(c.Item, note))
}

// errMessage is the user facing text of a userError or unique violation.
func errMessage(err error) string {
	_, msg := errStatus(err)
	return msg
}

// catalogApproval is the payload of a catalog app request (without an
// uploaded icon; Flathub icons are fetched again after the approval).
type catalogApproval struct {
	App catalogRow `json:"app"`
	New bool       `json:"new"`
}

// appNeedsApproval: required apps and apps with a vendor repository install
// as root without a user asking.
func (s *Server) appNeedsApproval(a api.CatalogApp) bool {
	if !s.settings().FourEyes {
		return false
	}
	if a.Mode == api.AppRequired {
		return true
	}
	for _, src := range a.Sources {
		if len(src.Repos) > 0 {
			return true
		}
	}
	return false
}

// writeCatalogApp inserts or updates an app and signs it.
func (s *Server) writeCatalogApp(ctx context.Context, tx pgx.Tx, app catalogRow, isNew bool) error {
	src, _ := json.Marshal(app.Sources)
	detect := append([]string{}, app.Detect...)
	scope := append([]int64{}, app.Scope...)
	var tag interface{ RowsAffected() int64 }
	var err error
	if isNew {
		tag, err = tx.Exec(ctx, `INSERT INTO catalog_apps(slug, name, summary, category, mode, enabled, sources, detect, scope)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (slug) DO NOTHING`,
			app.ID, app.Name, app.Summary, app.Category, app.Mode, app.Enabled, src, detect, scope)
	} else {
		tag, err = tx.Exec(ctx, `UPDATE catalog_apps SET name=$2, summary=$3, category=$4, mode=$5, enabled=$6, sources=$7, detect=$8, scope=$9,
			icon_tried=NULL, updated_at=now() WHERE slug=$1`,
			app.ID, app.Name, app.Summary, app.Category, app.Mode, app.Enabled, src, detect, scope)
	}
	if err == nil && tag.RowsAffected() == 0 {
		err = errAppExists
	}
	if err != nil {
		return err
	}
	return s.signCatalogApp(ctx, tx, app.ID)
}

func (s *Server) applyCatalogApproval(ctx context.Context, tx pgx.Tx, a approval, approver string) error {
	var c catalogApproval
	if err := json.Unmarshal(a.Payload, &c); err != nil {
		return err
	}
	if err := c.App.Validate(); err != nil {
		return errApproval(err.Error())
	}
	if err := s.writeCatalogApp(ctx, tx, c.App, c.New); errors.Is(err, errAppExists) {
		return errApproval("the app exists already or was deleted meanwhile")
	} else if err != nil {
		return err
	}
	src, _ := json.Marshal(c.App.Sources)
	return audit(ctx, tx, a.RequestedBy, "catalog.save", c.App.ID, string(src)+fmt.Sprintf(" (approval #%d by %s)", a.ID, approver))
}

// tokenApproval is the payload of an admin API token request. The token is
// created when approved and shown once to the approving admin, who hands it
// over (like new administrator credentials).
type tokenApproval struct {
	Name     string   `json:"name"`
	Role     string   `json:"role"`
	ReadOnly bool     `json:"read_only"`
	Days     int      `json:"days"`
	Scope    []string `json:"scope,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	Tenant   *int64   `json:"tenant,omitempty"`
}

// insertToken creates a token and returns it with its prefix and id.
func insertToken(ctx context.Context, tx pgx.Tx, t tokenApproval, createdBy string) (string, string, int64, error) {
	token := "lma_" + randToken(32)
	prefix := token[:12]
	var id int64
	err := tx.QueryRow(ctx, `INSERT INTO api_tokens(name, prefix, token_hash, role, read_only, created_by, expires_at, scope_tags, tenant_id, scopes)
		VALUES ($1,$2,$3,$4,$5,$6, now() + make_interval(days => $7), $8, $9, $10) RETURNING id`,
		t.Name, prefix, sha(token), t.Role, t.ReadOnly, createdBy, t.Days, append([]string{}, t.Scope...), t.Tenant, append([]string{}, t.Scopes...)).Scan(&id)
	return token, prefix, id, err
}

func applyTokenApproval(ctx context.Context, tx pgx.Tx, a approval, approver string) (string, error) {
	var t tokenApproval
	if err := json.Unmarshal(a.Payload, &t); err != nil {
		return "", err
	}
	token, prefix, _, err := insertToken(ctx, tx, t, a.RequestedBy)
	if err != nil {
		return "", err
	}
	err = audit(ctx, tx, a.RequestedBy, "api_token.create", t.Name, fmt.Sprintf("role=%s read_only=%t days=%d prefix=%s scope_tags=%s scopes=%s (approval #%d by %s)",
		t.Role, t.ReadOnly, t.Days, prefix, strings.Join(t.Scope, ","), strings.Join(t.Scopes, ","), a.ID, approver))
	return "API token " + t.Name + ": " + token, err
}
