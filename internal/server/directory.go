package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
	"golang.org/x/oauth2/jwt"
)

// The directory holds people and groups, provisioned by SCIM (Okta, Entra ID,
// authentik, JumpCloud) or synced from Google Workspace, which cannot push SCIM
// to custom apps. A device's primary user brings groups and department into
// blueprint rules, and groups can be assigned to blueprints directly.

type dirUser struct {
	ID          int64
	ExternalID  string
	Source      string
	UserName    string
	Email       string
	DisplayName string
	Department  string
	Title       string
	Active      bool
	Groups      []string
}

type dirGroup struct {
	ID         int64
	ExternalID string
	Source     string
	Name       string
	Members    int
	Blueprint  *int64
	Priority   *int
}

// directoryFacts adds the primary user's groups and department to the facts.
func directoryFacts(ctx context.Context, q pgx.Tx, deviceID string) (groups []string, dept string, err error) {
	err = q.QueryRow(ctx, `SELECT coalesce(u.department,''),
		coalesce((SELECT array_agg(g.name ORDER BY g.name) FROM dir_members m JOIN dir_groups g ON g.id=m.group_id WHERE m.user_id=u.id), '{}')
		FROM devices d JOIN dir_users u ON u.id=d.primary_user_id AND u.active WHERE d.id=$1`, deviceID).Scan(&dept, &groups)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil
	}
	return groups, dept, err
}

// groupBlueprint returns the blueprint assigned to one of the primary user's
// groups (lowest priority number wins), or nil.
func groupBlueprint(ctx context.Context, q pgx.Tx, deviceID string) (*int64, error) {
	var id int64
	err := q.QueryRow(ctx, `SELECT a.blueprint_id FROM devices d
		JOIN dir_users u ON u.id=d.primary_user_id AND u.active
		JOIN dir_members m ON m.user_id=u.id
		JOIN blueprint_group_assignments a ON a.group_id=m.group_id
		WHERE d.id=$1 ORDER BY a.priority, a.group_id LIMIT 1`, deviceID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &id, err
}

// ---- directory pages ----

func (s *Server) directoryPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderDirectory(w, r, sess, "", "", "")
}

func (s *Server) renderDirectory(w http.ResponseWriter, r *http.Request, sess session, token, msg, errMsg string) {
	ctx := r.Context()
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	rows, err := s.db.Query(ctx, `SELECT u.id, u.external_id, u.source, u.user_name, u.email, u.display_name, u.department, u.title, u.active,
		coalesce((SELECT array_agg(g.name ORDER BY g.name) FROM dir_members m JOIN dir_groups g ON g.id=m.group_id WHERE m.user_id=u.id), '{}')
		FROM dir_users u WHERE $1 = '' OR lower(u.email || ' ' || u.display_name || ' ' || u.department) LIKE '%' || $1 || '%'
		ORDER BY u.active DESC, u.display_name, u.email LIMIT 500`, q)
	if err != nil {
		s.fail(w, err)
		return
	}
	users, err := pgx.CollectRows(rows, pgx.RowToStructByPos[dirUser])
	if err != nil {
		s.fail(w, err)
		return
	}
	groups, err := s.dirGroups(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	bps, err := s.allBlueprints(ctx, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	gs, err := s.googleSettings(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	var scimSet bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM settings WHERE key='scim')`).Scan(&scimSet); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, sess, "directory", map[string]any{"Users": users, "Groups": groups, "Blueprints": bps, "Q": q,
		"Token": token, "Msg": msg, "Error": errMsg, "SCIMSet": scimSet, "SCIMURL": s.cfg.PublicURL + "/scim/v2",
		"Google": gs, "GoogleConfigured": gs.KeyEnc != ""})
}

func (s *Server) dirGroups(ctx context.Context) ([]dirGroup, error) {
	rows, err := s.db.Query(ctx, `SELECT g.id, g.external_id, g.source, g.name,
		(SELECT count(*) FROM dir_members m WHERE m.group_id=g.id), a.blueprint_id, a.priority
		FROM dir_groups g LEFT JOIN blueprint_group_assignments a ON a.group_id=g.id ORDER BY g.name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[dirGroup])
}

// groupAssign maps a directory group to a blueprint, or removes the mapping.
func (s *Server) groupAssign(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	gid, err := strconv.ParseInt(r.FormValue("group_id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid group", http.StatusBadRequest)
		return
	}
	bp, _ := strconv.ParseInt(r.FormValue("blueprint_id"), 10, 64)
	prio, err := strconv.Atoi(r.FormValue("priority"))
	if err != nil || prio < 0 || prio > 10000 {
		prio = 100
	}
	err = s.auditAction(ctx, sess.Email, "directory.group_assign", strconv.FormatInt(gid, 10), fmt.Sprintf("blueprint=%d priority=%d", bp, prio), func(tx pgx.Tx) error {
		if bp == 0 {
			_, err := tx.Exec(ctx, `DELETE FROM blueprint_group_assignments WHERE group_id=$1`, gid)
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO blueprint_group_assignments(group_id, blueprint_id, priority) VALUES ($1,$2,$3)
			ON CONFLICT (group_id) DO UPDATE SET blueprint_id=EXCLUDED.blueprint_id, priority=EXCLUDED.priority`, gid, bp, prio)
		return err
	})
	if err != nil {
		s.renderDirectory(w, r, sess, "", "", err.Error())
		return
	}
	http.Redirect(w, r, "/directory#groups", http.StatusSeeOther)
}

// scimToken creates a new SCIM bearer token; only its hash is stored.
func (s *Server) scimToken(w http.ResponseWriter, r *http.Request, sess session) {
	tok := "lms_" + randToken(32)
	doc, _ := json.Marshal(map[string]string{"token_sha256": fmt.Sprintf("%x", sha(tok))})
	err := s.auditAction(r.Context(), sess.Email, "directory.scim_token", "scim", "token rotated", func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `INSERT INTO settings(key, value) VALUES ('scim', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, string(doc))
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.renderDirectory(w, r, sess, tok, "New SCIM token created; the previous one stopped working.", "")
}

// ---- Google Workspace sync ----

type googleSettings struct {
	AdminEmail string    `json:"admin_email"`
	KeyEnc     string    `json:"key_enc"`
	LastSync   time.Time `json:"last_sync"`
	LastResult string    `json:"last_result"`
}

func (s *Server) googleSettings(ctx context.Context) (googleSettings, error) {
	var g googleSettings
	var raw []byte
	err := s.db.QueryRow(ctx, `SELECT value FROM settings WHERE key='google'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return g, nil
	}
	if err != nil {
		return g, err
	}
	return g, json.Unmarshal(raw, &g)
}

func (s *Server) saveGoogle(ctx context.Context, g googleSettings) error {
	doc, _ := json.Marshal(g)
	_, err := s.db.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('google', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, string(doc))
	return err
}

type serviceAccount struct {
	ClientEmail  string `json:"client_email"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyID string `json:"private_key_id"`
	TokenURI     string `json:"token_uri"`
}

func (s *Server) googleConfigure(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	g, err := s.googleSettings(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	g.AdminEmail = strings.ToLower(strings.TrimSpace(r.FormValue("admin_email")))
	if key := strings.TrimSpace(r.FormValue("service_account")); key != "" {
		var sa serviceAccount
		if err := json.Unmarshal([]byte(key), &sa); err != nil || sa.ClientEmail == "" || sa.PrivateKey == "" {
			s.renderDirectory(w, r, sess, "", "", "paste the service account JSON key file")
			return
		}
		if g.KeyEnc, err = s.seal32(key); err != nil {
			s.fail(w, err)
			return
		}
	}
	if !strings.Contains(g.AdminEmail, "@") || g.KeyEnc == "" {
		s.renderDirectory(w, r, sess, "", "", "service account key and an admin email for delegation are required")
		return
	}
	if err := s.auditAction(ctx, sess.Email, "directory.google_configure", g.AdminEmail, "service account updated", func(pgx.Tx) error { return s.saveGoogle(ctx, g) }); err != nil {
		s.fail(w, err)
		return
	}
	s.googleSyncNow(w, r, sess)
}

func (s *Server) googleSyncNow(w http.ResponseWriter, r *http.Request, sess session) {
	res, err := s.syncGoogle(r.Context())
	if err != nil {
		s.renderDirectory(w, r, sess, "", "", "Google sync failed: "+err.Error())
		return
	}
	s.renderDirectory(w, r, sess, "", "Google sync: "+res, "")
}

// googleSyncLoop syncs hourly while configured.
func (s *Server) googleSyncLoop(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if g, err := s.googleSettings(ctx); err == nil && g.KeyEnc != "" {
				if _, err := s.syncGoogle(ctx); err != nil {
					s.log.Error("google directory sync", "err", err)
				}
			}
		}
	}
}

// googleTokenURL is pinned: the token_uri inside an uploaded key is ignored,
// so a crafted key cannot send the signed assertion to another host.
const googleTokenURL = "https://oauth2.googleapis.com/token" //nolint:gosec // public endpoint URL, not a credential

const googleScopes = "https://www.googleapis.com/auth/admin.directory.user.readonly " +
	"https://www.googleapis.com/auth/admin.directory.group.readonly https://www.googleapis.com/auth/admin.directory.group.member.readonly"

func (s *Server) syncGoogle(ctx context.Context) (string, error) {
	g, err := s.googleSettings(ctx)
	if err != nil || g.KeyEnc == "" {
		return "", errors.Join(err, errors.New("not configured"))
	}
	key, err := s.open32(g.KeyEnc)
	if err != nil {
		return "", err
	}
	var sa serviceAccount
	if err := json.Unmarshal([]byte(key), &sa); err != nil {
		return "", err
	}
	conf := &jwt.Config{Email: sa.ClientEmail, PrivateKey: []byte(sa.PrivateKey), PrivateKeyID: sa.PrivateKeyID,
		Scopes: strings.Fields(googleScopes), TokenURL: googleTokenURL, Subject: g.AdminEmail}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	client := conf.Client(ctx)
	users, err := googleList[struct {
		ID           string `json:"id"`
		PrimaryEmail string `json:"primaryEmail"`
		Suspended    bool   `json:"suspended"`
		Name         struct {
			FullName string `json:"fullName"`
		} `json:"name"`
		Organizations []struct {
			Department string `json:"department"`
			Title      string `json:"title"`
			Primary    bool   `json:"primary"`
		} `json:"organizations"`
	}](ctx, client, "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=500&projection=basic", "users")
	if err != nil {
		return "", err
	}
	groups, err := googleList[struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}](ctx, client, "https://admin.googleapis.com/admin/directory/v1/groups?customer=my_customer&maxResults=200", "groups")
	if err != nil {
		return "", err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	seen := map[string]int64{}
	for _, u := range users {
		var dept, title string
		for _, o := range u.Organizations {
			if o.Primary || dept == "" {
				dept, title = o.Department, o.Title
			}
		}
		var id int64
		email := strings.ToLower(u.PrimaryEmail)
		if err := tx.QueryRow(ctx, `INSERT INTO dir_users(external_id, source, user_name, email, display_name, department, title, active)
			VALUES ($1,'google',$2,$2,$3,$4,$5,$6)
			ON CONFLICT (email) DO UPDATE SET external_id=EXCLUDED.external_id, source='google', display_name=EXCLUDED.display_name,
			department=EXCLUDED.department, title=EXCLUDED.title, active=EXCLUDED.active, updated_at=now() RETURNING id`,
			u.ID, email, u.Name.FullName, dept, title, !u.Suspended).Scan(&id); err != nil {
			return "", err
		}
		seen[u.ID] = id
	}
	// people removed in Google lose access here too
	ids := make([]string, 0, len(seen))
	for ext := range seen {
		ids = append(ids, ext)
	}
	if _, err := tx.Exec(ctx, `UPDATE dir_users SET active=false, updated_at=now() WHERE source='google' AND NOT (external_id = ANY($1))`, ids); err != nil {
		return "", err
	}
	for _, gr := range groups {
		var gid int64
		if err := tx.QueryRow(ctx, `INSERT INTO dir_groups(external_id, source, name) VALUES ($1,'google',$2)
			ON CONFLICT (source, external_id) DO UPDATE SET name=EXCLUDED.name, updated_at=now() RETURNING id`, gr.ID, firstNonEmpty(gr.Email, gr.Name)).Scan(&gid); err != nil {
			return "", err
		}
		members, err := googleList[struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}](ctx, client, "https://admin.googleapis.com/admin/directory/v1/groups/"+url.PathEscape(gr.ID)+"/members?maxResults=200", "members")
		if err != nil {
			return "", err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM dir_members WHERE group_id=$1`, gid); err != nil {
			return "", err
		}
		for _, m := range members {
			if uid, ok := seen[m.ID]; ok && m.Type == "USER" {
				if _, err := tx.Exec(ctx, `INSERT INTO dir_members(group_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, gid, uid); err != nil {
					return "", err
				}
			}
		}
	}
	res := fmt.Sprintf("%d users, %d groups", len(users), len(groups))
	g.LastSync, g.LastResult = time.Now().UTC(), res
	doc, _ := json.Marshal(g)
	if _, err := tx.Exec(ctx, `UPDATE settings SET value=$1, updated_at=now() WHERE key='google'`, string(doc)); err != nil {
		return "", err
	}
	if err := audit(ctx, tx, "system", "directory.google_sync", "google", res); err != nil {
		return "", err
	}
	return res, tx.Commit(ctx)
}

// googleList follows nextPageToken for a Directory API collection.
func googleList[T any](ctx context.Context, c *http.Client, base, field string) ([]T, error) {
	var out []T
	page := ""
	for range 200 { // hard stop for runaway paging
		u := base
		if page != "" {
			u += "&pageToken=" + url.QueryEscape(page)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			// upstream bodies go to the log only, never to the UI
			slog.Default().Error("google directory api", "status", resp.Status, "body", string(body[:min(len(body), 500)]))
			return nil, fmt.Errorf("google directory API returned %s", resp.Status)
		}
		var res map[string]json.RawMessage
		if err := json.Unmarshal(body, &res); err != nil {
			return nil, err
		}
		var items []T
		if raw, ok := res[field]; ok {
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, err
			}
		}
		out = append(out, items...)
		page = ""
		if raw, ok := res["nextPageToken"]; ok {
			_ = json.Unmarshal(raw, &page)
		}
		if page == "" {
			return out, nil
		}
	}
	return nil, errors.New("too many pages")
}

// activeUsers drops device users whose directory entry is inactive. Users
// without a directory entry (local assignments) stay.
func activeUsers(ctx context.Context, tx pgx.Tx, users []api.User) ([]api.User, error) {
	if len(users) == 0 {
		return users, nil
	}
	rows, err := tx.Query(ctx, `SELECT lower(email) FROM dir_users WHERE NOT active`)
	if err != nil {
		return nil, err
	}
	inactive, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := users[:0:0]
	for _, u := range users {
		if !slices.Contains(inactive, strings.ToLower(u.Email)) {
			out = append(out, u)
		}
	}
	return out, nil
}
