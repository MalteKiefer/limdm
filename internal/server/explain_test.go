package server

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestExplainFleet fills the test database with a generated fleet (50,000
// devices and directory users) and checks that the hot and list queries use
// their indexes. It takes a minute, so it runs only with LIMDM_TEST_EXPLAIN=1;
// -v prints the plans.
func TestExplainFleet(t *testing.T) {
	if os.Getenv("LIMDM_TEST_EXPLAIN") == "" {
		t.Skip("LIMDM_TEST_EXPLAIN not set")
	}
	db := loadTestDB(t, 4)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `SET statement_timeout = 0;
		INSERT INTO dir_users(source, user_name, email, active, previous_emails)
			SELECT 'scim', 'u'||i, 'u'||i||'@x.test', i % 20 <> 0, CASE WHEN i % 10 = 0 THEN ARRAY['old'||i||'@x.test'] ELSE '{}' END
			FROM generate_series(1, 50000) i;
		INSERT INTO devices(id, cert_serial, cert_not_after, hostname, machine_id, last_seen, tags, users, inventory, checks, packages, retired)
			SELECT 'd'||i, 's', now(), 'pc'||lpad(i::text, 6, '0'), md5(i::text), now(), ARRAY['t'||(i % 50)],
				jsonb_build_array(jsonb_build_object('username', 'u'||i, 'email', 'u'||i||'@x.test')),
				jsonb_build_object('apps', jsonb_build_array(jsonb_build_object('id', 'app'||(i % 30), 'installed', true)),
					'flatpaks', jsonb_build_array(jsonb_build_object('id', 'org.fp'||(i % 40))),
					'flatpak_remotes', jsonb_build_array(jsonb_build_object('name', 'flathub'))),
				(SELECT jsonb_agg(jsonb_build_object('id', 'check'||c, 'status', CASE WHEN (i + c) % 97 = 0 THEN 'fail' ELSE 'pass' END)) FROM generate_series(1, 20) c),
				(SELECT jsonb_agg(jsonb_build_object('n', 'pkg'||p, 'v', '1.'||(i % 7)||'.'||p)) FROM generate_series(1, 200) p)
					|| CASE WHEN i % 500 = 0 THEN '[{"n":"rare","v":"2.0"}]'::jsonb ELSE '[]'::jsonb END,
				i % 100 = 0
			FROM generate_series(1, 50000) i;
		ANALYZE`); err != nil {
		t.Fatal(err)
	}
	pkgVer, pkgArgs, _ := pkgCond("rare < 3.0")
	where := func(key string) string {
		for _, f := range deviceFilters {
			if f.Key == key {
				return f.Where
			}
		}
		t.Fatal(key)
		return ""
	}
	list := `SELECT d.id, d.hostname, coalesce(b.name, 'default')` + deviceFrom
	for _, c := range []struct {
		name, sql, index string
		args             []any
	}{
		{"poll: disabled device users", `SELECT EXISTS (
			SELECT 1 FROM devices d, jsonb_array_elements(d.users) u
			WHERE d.id=$1 AND d.last_seen IS NOT NULL
			AND NOT EXISTS (SELECT 1 FROM dir_users a WHERE a.active AND lower(a.email)=lower(u->>'email')) AND (
				EXISTS (SELECT 1 FROM dir_users du WHERE lower(du.email)=lower(u->>'email') AND NOT du.active AND du.updated_at > d.last_seen)
				OR EXISTS (SELECT 1 FROM dir_users du WHERE du.previous_emails @> ARRAY[lower(u->>'email')] AND NOT du.active AND du.updated_at > d.last_seen)
				OR EXISTS (SELECT 1 FROM dir_tombstones t WHERE t.email=lower(u->>'email') AND t.removed_at > d.last_seen)))`,
			"dir_users_lower_email", []any{"d20"}},
		{"check in: activeUsers", `SELECT e FROM unnest($1::text[]) e WHERE
			NOT EXISTS (SELECT 1 FROM dir_users WHERE active AND lower(email) = e)
			AND (EXISTS (SELECT 1 FROM dir_users WHERE NOT active AND lower(email) = e)
			OR EXISTS (SELECT 1 FROM dir_users WHERE NOT active AND previous_emails @> ARRAY[e])
			OR EXISTS (SELECT 1 FROM dir_tombstones WHERE email = e))`, "dir_users_previous_emails", []any{[]string{"u20@x.test", "old10@x.test"}}},
		{"sign in: memberGroups", `SELECT g.name FROM dir_groups g JOIN dir_members m ON m.group_id=g.id
			JOIN dir_users u ON u.id=m.user_id WHERE lower(u.email)=$1 AND u.active`, "dir_users_lower_email", []any{"u7@x.test"}},
		{"enroll: same machine", `SELECT id FROM devices WHERE machine_id=$1 AND id<>$2 AND NOT retired AND tenant_id=$3`,
			"devices_machine_id", []any{"c4ca4238a0b923820dcc509a6f75849b", "x", 1}},
		{"API: device page", list + ` WHERE TRUE ORDER BY d.hostname, d.id LIMIT 101`, "devices_hostname", nil},
		{"API: next device page", list + ` WHERE (d.hostname, d.id) > ($1, $2) ORDER BY d.hostname, d.id LIMIT 101`, "devices_hostname", []any{"pc025000", "d25000"}},
		{"console: device page", list + ` WHERE TRUE ORDER BY d.retired, d.hostname, d.id LIMIT 200`, "devices_retired_hostname", nil},
		{"filter tag", list + ` WHERE ` + where("tag"), "devices_tags", []any{"t7"}},
		{"filter app", list + ` WHERE ` + where("app"), "devices_apps", []any{"app3"}},
		{"filter flatpak", list + ` WHERE ` + where("flatpak"), "devices_flatpaks", []any{"org.fp3"}},
		{"filter remote", list + ` WHERE ` + where("remote") + ` LIMIT 200`, "", []any{"flathub"}},
		{"filter failing", list + ` WHERE ` + where("failing"), "devices_checks", []any{"check5"}},
		{"filter pkg with version", list + ` WHERE ` + pkgVer, "devices_packages", pkgArgs},
		{"retention: finished commands", `DELETE FROM commands WHERE status IN ('ok', 'failed', 'expired') AND updated_at < now() - interval '180 days'
			AND type NOT IN ('lock', 'unlock', 'lost', 'found', 'wipe')`, "", nil},
	} {
		rows, err := db.Query(ctx, `EXPLAIN (ANALYZE, COSTS OFF, SUMMARY ON) `+c.sql, c.args...)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		plan := strings.Join(lines, "\n")
		t.Logf("%s:\n%s", c.name, plan)
		if c.index != "" && !strings.Contains(plan, c.index) {
			t.Errorf("%s does not use %s", c.name, c.index)
		}
	}
}
