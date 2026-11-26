package server

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/maltekiefer/limdm/internal/api"
)

// In console help: the glossary page, short explanations of declaration
// types and status terms, readable audit action names and links into the
// documentation. Every English text here is a translation key.

// docsURL is the documentation of the project on GitHub; pages link into it.
const docsURL = "https://github.com/MalteKiefer/limdm/blob/main/docs/"

// typeInfo describes every declaration type for the type picker and links
// its section in docs/declarations.md (TestTypeInfo checks both).
var typeInfo = map[string]struct{ Desc, Anchor string }{
	api.TypeAgent:          {"How often the agent checks in, and the offline lock after a long time without server contact.", "comlimdmagent"},
	api.TypeCompliance:     {"Compliance level (L1 or L2), automatic remediation, exceptions, grace period and automatic lock.", "comlimdmcompliance"},
	api.TypePrivacy:        {"Which inventory data the agent collects (network details, signed in users).", "comlimdmprivacy"},
	api.TypeUpdates:        {"Automatic operating system updates: mode, time window, reboot.", "comlimdmupdates"},
	api.TypePackages:       {"System packages to install or remove.", "comlimdmpackages-list"},
	api.TypeFlatpak:        {"Flatpak remotes and apps to install or remove.", "comlimdmflatpak-list"},
	api.TypeRepositories:   {"Additional signed package repositories for apt or dnf.", "comlimdmrepositories-list"},
	api.TypeServices:       {"systemd services to enable, disable or mask.", "comlimdmservices-list"},
	api.TypeFiles:          {"Files with fixed content, owner and mode.", "comlimdmfiles-list"},
	api.TypeCertificates:   {"CA certificates added to the system trust store.", "comlimdmcertificates-list"},
	api.TypeSysctl:         {"Kernel parameters (sysctl).", "comlimdmsysctl-list-comlimdmkernelmodules-list"},
	api.TypeKernelModules:  {"Kernel modules that must not load.", "comlimdmsysctl-list-comlimdmkernelmodules-list"},
	api.TypeDNS:            {"DNS servers and search domains.", "comlimdmdns-comlimdmntp-comlimdmproxy"},
	api.TypeNTP:            {"Time servers.", "comlimdmdns-comlimdmntp-comlimdmproxy"},
	api.TypeProxy:          {"System wide HTTP and HTTPS proxy.", "comlimdmdns-comlimdmntp-comlimdmproxy"},
	api.TypeScripts:        {"Shell scripts the agent runs as root on an interval.", "comlimdmscripts-list"},
	api.TypeFirewall:       {"Host firewall: inbound traffic denied except the listed ports.", "comlimdmfirewall-list"},
	api.TypeSSH:            {"SSH server options that cannot weaken the baseline.", "comlimdmssh-list-comlimdmbanner"},
	api.TypeBanner:         {"Text shown before login on the console, over SSH and on the login screen.", "comlimdmssh-list-comlimdmbanner"},
	api.TypeScreenLock:     {"Screen lock after idle time, and login screen privacy.", "comlimdmscreenlock"},
	api.TypeSudo:           {"sudo rules for users and groups.", "comlimdmsudo-list"},
	api.TypePolkit:         {"polkit rules that allow or deny system actions to groups.", "comlimdmpolkit-list"},
	api.TypeSoftwareStore:  {"What users may install from the software stores.", "comlimdmsoftwarestore"},
	api.TypeBootloader:     {"GRUB password against editing boot entries.", "comlimdmbootloader"},
	api.TypeDiskEncryption: {"Escrow of LUKS recovery keys with the server.", "comlimdmdiskencryption"},
	api.TypeLogin:          {"Desktop login with the central identity provider (OIDC).", "comlimdmlogin"},
	api.TypeOSVersion:      {"Minimum operating system versions per distribution.", "comlimdmosversion-list"},
}

// typeMeta is what the library item editor needs per type: description,
// documentation link and field reference, translated.
type typeMeta struct {
	Desc   string     `json:"desc"`
	Doc    string     `json:"doc"`
	Fields [][]string `json:"fields"` // path, kind
}

func itemMeta(lang string) map[string]typeMeta {
	m := make(map[string]typeMeta, len(api.Types))
	for t := range api.Types {
		tm := typeMeta{Desc: translate(lang, typeInfo[t].Desc), Doc: docsURL + "declarations.md#" + typeInfo[t].Anchor}
		for _, f := range api.PayloadFields(t) {
			tm.Fields = append(tm.Fields, []string{f.Path, kindText(lang, f.Kind)})
		}
		m[t] = tm
	}
	return m
}

// kindText translates "list of text" style kinds word by word.
func kindText(lang, k string) string {
	for _, p := range []string{"list of ", "object of "} {
		if rest, ok := strings.CutPrefix(k, p); ok {
			return translate(lang, strings.TrimSpace(p)) + " " + kindText(lang, rest)
		}
	}
	return translate(lang, k)
}

// statusHelp explains the device states (pill tooltips, glossary).
var statusHelp = map[string]string{
	"compliant":     "Every counted check passes.",
	"in grace":      "Checks fail, but the grace period of the compliance item is still running; no action is taken yet.",
	"non-compliant": "At least one check fails and the grace period is over; notification and automatic lock follow if the compliance item sets them.",
	"stale":         "Silent: no check in for longer than the stale threshold in the settings, so the shown state may be outdated.",
	"pending":       "No report: enrolled, but the device has not sent compliance results yet.",
	"retired":       "No longer managed; the certificate is revoked and the device cannot check in.",
	// check results
	"pass":     "The check passed at the last report.",
	"fail":     "The check failed at the last report.",
	"excepted": "Documented exception: excluded on purpose in the compliance item, never counted as passed.",
	"na":       "Not applicable on this device.",
}

// glossary lists the terms the console uses, with a documentation page.
var glossary = []struct{ Term, Text, Doc string }{
	{"Agent", "The service on each device. It enforces the configuration, runs the checks and reports back.", "agent.md"},
	{"Audit log", "Append only record of every change and every sensitive view, protected by a hash chain.", "security.md#audit-log"},
	{"Blueprint", "Rule tree that decides which library items a device gets. Every device has exactly one blueprint; a blueprint can inherit from a parent.", "concepts.md#blueprints"},
	{"Blueprint source", "Where the blueprint of a device comes from: set on the device (manually or by its enrollment token), else the directory group of its primary user with the lowest priority number, else default.", "concepts.md#which-blueprint-a-device-gets"},
	{"Check", "One compliance test the agent runs, for example disk encryption. Results are pass, fail, excepted or not applicable.", "compliance.md#checks"},
	{"Check in", "The agent contacting the server: it sends inventory and check results and fetches configuration and commands. The interval is set in the agent item.", "concepts.md#agent-cycle"},
	{"CIDR", "Network notation of address and prefix length, for example 10.0.0.0/8 for every address starting with 10.", ""},
	{"Configuration", "The effective set of declarations of a device: its blueprint chain resolved and merged.", "concepts.md#merging"},
	{"Declaration", "One desired state the agent enforces, for example installed packages or a screen lock. A library item becomes a declaration on the device.", "concepts.md#declarations"},
	{"Enrollment token", "One time secret that lets a new device join and receive its client certificate. It can set the blueprint of the device.", "installation.md#after-the-first-sign-in"},
	{"Exception", "A check excluded on purpose (exclude in the compliance item); shown as excepted, never as passed.", "compliance.md#policy-comlimdmcompliance"},
	{"Grace period", "How long a device with failing checks stays in grace before it counts as non-compliant (grace_hours). When it ends, the webhook is sent if notify is on; lock_after_hours locks the device that long after it became non-compliant (0 never locks).", "compliance.md#policy-comlimdmcompliance"},
	{"L1 and L2", "Compliance levels. L1 is the baseline for every device (CIS Level 1, BSI basic). L2 adds strict checks (CIS Level 2) that can limit how a device is used.", "compliance.md#levels"},
	{"Library item", "A named, reusable declaration: a type plus JSON settings. Blueprints assign library items to devices.", "concepts.md#library"},
	{"Lock", "Blocks every new login and locks running sessions until the device is unlocked. Data stays. Reversible.", "concepts.md#commands"},
	{"Lost mode", "Lock plus a message on the screen. With an escrowed recovery key the other disk key slots are removed, so after power off only IT can open the disk. Reversible with End lost mode.", "disk-encryption.md#lost-or-stolen-devices"},
	{"LUKS", "The Linux disk encryption. LiMDM escrows its recovery keys and wipes its headers on a wipe.", "disk-encryption.md"},
	{"mTLS", "Mutual TLS: server and agent both prove their identity with certificates. The agent endpoint accepts only devices with a valid client certificate.", "security.md#agent-channel"},
	{"NSS", "Name Service Switch: how Linux finds users and groups, in local files or in directory services such as sssd, LDAP or winbind.", ""},
	{"OIDC", "OpenID Connect: sign in through an identity provider such as Google, Entra ID or Keycloak.", "configuration.md"},
	{"Pilot tag", "Devices with this tag get a newly approved agent version at once; the others follow after the delay.", "operations.md#releases-and-agent-updates"},
	{"Recovery key", "LUKS key that opens an encrypted disk without the user's passphrase. Every view is recorded in the audit log.", "disk-encryption.md"},
	{"Remediation", "The agent fixes a failing check automatically when the compliance item has remediate on.", "compliance.md#checks"},
	{"Remote", "A Flatpak repository, for example Flathub, that apps are installed from.", "software.md#flatpak-remotes"},
	{"Retire", "Ends management: the client certificate is revoked and the device can no longer check in. Data on the device and its history in the console stay. Not reversible; the device must enroll again.", "concepts.md#commands"},
	{"SCIM", "Standard to sync users and groups from an identity provider into the directory.", "concepts.md#directory"},
	{"Wipe", "Erases the disk encryption headers: all data on the device is lost for good. Only for encrypted devices.", "disk-encryption.md#lost-or-stolen-devices"},
}

// auditActions names audit log actions; command.<type> uses the command name.
var auditActions = map[string]string{
	"agent.tamper": "Tamper attempt", "agent.update": "Agent updated", "agent.update_failed": "Agent update failed",
	"agent_release.block": "Agent version blocked", "agent_update.request": "Agent update requested", "agent_updates.policy": "Agent update policy changed",
	"blueprint.delete": "Blueprint deleted", "blueprint.save": "Blueprint saved",
	"catalog.delete": "Catalog app deleted", "catalog.import": "App added to the catalog", "catalog.save": "Catalog app saved", "catalog.settings": "Software settings changed",
	"command.failed": "Command failed", "command.result": "Command result",
	"compliance.lock": "Locked by compliance policy", "compliance.unlock": "Unlocked by compliance policy", "compliance.notify": "Non-compliance notified",
	"device.assign": "Device details changed", "device.cert_activate": "Device certificate activated", "device.cert_renew": "Device certificate renewed",
	"device.duplicate": "Duplicate device", "device.enroll": "Device enrolled", "device.enrolled": "Device enrolled", "device.noncompliant": "Device non-compliant",
	"device.retire": "Device retired", "device.tamper": "Tamper attempt", "device.unknown": "Unknown device", "device.tag-add": "Tag added", "device.tag-remove": "Tag removed",
	"directory.google_configure": "Google directory configured", "directory.google_sync": "Google directory synced", "directory.group_assign": "Group blueprint assigned",
	"directory.scim_token": "SCIM token created", "directory.user_disabled": "Directory user disabled",
	"export": "Export downloaded", "library.delete": "Library item deleted", "library.save": "Library item saved",
	"login": "Signed in", "login.denied": "Sign in denied", "login.local.failed": "Local sign in failed", "logout": "Signed out",
	"profile.password": "Own password changed", "profile.password_check_failed": "Wrong current password", "profile.recovery_codes": "Recovery codes created",
	"profile.totp": "Authenticator changed", "recovery.escrow": "Recovery key escrowed", "recovery.view": "Recovery key viewed",
	"settings.save": "Settings saved", "token.create": "Enrollment token created", "token.revoke": "Enrollment token revoked",
	"user.add": "Console user added", "user.reset": "Console user credentials reset", "user.update": "Console user changed",
	"notification.channel_add": "Notification channel added",
}

// auditLabel is the readable name of an audit action, or the code itself.
func auditLabel(lang, action string, cmdLabel func(string) string) string {
	if l, ok := auditActions[action]; ok {
		return translate(lang, l)
	}
	if typ, ok := strings.CutPrefix(action, "command."); ok {
		if l := cmdLabel(typ); l != "" {
			return translate(lang, "Command") + ": " + l
		}
	}
	return action
}

// checkDetail translates the fixed part of a check detail from the agent:
// the whole text, or a known prefix such as "not encrypted: " before data.
func checkDetail(lang, d string) string {
	if lang != "de" || d == "" {
		return d
	}
	if t := translate(lang, d); t != d {
		return t
	}
	best := ""
	for _, p := range checkDetailPrefixes {
		if strings.HasPrefix(d, p) && len(p) > len(best) {
			best = p
		}
	}
	if best == "" {
		return d
	}
	return translate(lang, best) + d[len(best):]
}

// checkDetailPrefixes are agent detail texts followed by device data.
var checkDetailPrefixes = []string{"not encrypted: ", "encrypted: ", "missing: ", "not enforced: ", "empty password: ",
	"other UID 0 accounts: ", "unapproved admins in ", "no recovery key escrowed for ", "update status unknown: ",
	"osquery is not packaged for ", "GRUB password set in ", "documented exception (risk accepted)"}

// helpPage shows the glossary, the roles and links into the documentation.
func (s *Server) helpPage(w http.ResponseWriter, r *http.Request, sess session) {
	lang := requestLang(r)
	type entry struct{ ID, Term, Text, Doc string }
	list := make([]entry, 0, len(glossary))
	for _, g := range glossary {
		e := entry{ID: strings.ReplaceAll(strings.ToLower(g.Term), " ", "-"), Term: translate(lang, g.Term), Text: translate(lang, g.Text)}
		if g.Doc != "" {
			e.Doc = docsURL + g.Doc
		}
		list = append(list, e)
	}
	sort.SliceStable(list, func(i, j int) bool { return strings.ToLower(list[i].Term) < strings.ToLower(list[j].Term) })
	s.render(w, r, sess, "help", map[string]any{"Terms": list, "Statuses": []string{"compliant", "in grace", "non-compliant", "stale", "pending", "retired"}})
}

// bpSource says where the blueprint of a device comes from, in the order
// resolveDevice applies: set on the device (by an admin or the enrollment
// token), the primary user's directory group with the lowest priority
// number, or the default blueprint.
type bpSource struct {
	Kind     string // "device", "group" or "default"
	Group    string
	Priority int
}

func (s *Server) blueprintSource(ctx context.Context, deviceID string) (bpSource, error) {
	var direct bool
	var group *string
	var prio *int
	err := s.db.QueryRow(ctx, `SELECT d.blueprint_id IS NOT NULL,
		(SELECT g.name FROM dir_users u JOIN dir_members m ON m.user_id=u.id JOIN blueprint_group_assignments a ON a.group_id=m.group_id
		 JOIN dir_groups g ON g.id=a.group_id WHERE u.id=d.primary_user_id AND u.active ORDER BY a.priority, a.group_id LIMIT 1),
		(SELECT a.priority FROM dir_users u JOIN dir_members m ON m.user_id=u.id JOIN blueprint_group_assignments a ON a.group_id=m.group_id
		 WHERE u.id=d.primary_user_id AND u.active ORDER BY a.priority, a.group_id LIMIT 1)
		FROM devices d WHERE d.id=$1`, deviceID).Scan(&direct, &group, &prio)
	switch {
	case err != nil:
		return bpSource{}, err
	case direct:
		return bpSource{Kind: "device"}, nil
	case group != nil && prio != nil:
		return bpSource{Kind: "group", Group: *group, Priority: *prio}, nil
	}
	return bpSource{Kind: "default"}, nil
}

// bpAssignments are, per blueprint, the devices that have it set directly
// and the directory groups that assign it with their priority.
type bpAssignments struct {
	Direct int
	Groups []bpSource
}

func (s *Server) blueprintAssignments(ctx context.Context) (map[int64]*bpAssignments, error) {
	m := map[int64]*bpAssignments{}
	get := func(id int64) *bpAssignments {
		if m[id] == nil {
			m[id] = &bpAssignments{}
		}
		return m[id]
	}
	rows, err := s.db.Query(ctx, `SELECT blueprint_id, count(*) FROM devices WHERE NOT retired AND blueprint_id IS NOT NULL GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			rows.Close()
			return nil, err
		}
		get(id).Direct = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = s.db.Query(ctx, `SELECT a.blueprint_id, g.name, a.priority FROM blueprint_group_assignments a JOIN dir_groups g ON g.id=a.group_id ORDER BY a.priority, g.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		src := bpSource{Kind: "group"}
		if err := rows.Scan(&id, &src.Group, &src.Priority); err != nil {
			return nil, err
		}
		get(id).Groups = append(get(id).Groups, src)
	}
	return m, rows.Err()
}
