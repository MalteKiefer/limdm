package server

import (
	"net/http"
	"strings"

	"github.com/maltekiefer/limdm/internal/api"
)

// Form hints for the declaration schemas of GET /api/v1/schemas/{type}:
// titles, help texts, sections, choices, widgets and limits per field, in
// English and German. The schema itself comes from the Go types
// (internal/api/schema.go); the hints only describe it. Limits and choices
// repeat what the Validate functions of internal/api accept, never more
// strictly (TestSchemaHints checks every path and the example payloads).

// tr is an English text and its German translation.
type tr [2]string

type schemaHint struct {
	T, D, Sec tr
	Widget    string // textarea, code, secret, checkboxes
	Enum      []any
	EnumT     []tr
	Min, Max  *int
	Def       any
}

func h(en, de string) schemaHint                         { return schemaHint{T: tr{en, de}} }
func (x schemaHint) d(en, de string) schemaHint          { x.D = tr{en, de}; return x }
func (x schemaHint) sec(en, de string) schemaHint        { x.Sec = tr{en, de}; return x }
func (x schemaHint) w(widget string) schemaHint          { x.Widget = widget; return x }
func (x schemaHint) def(v any) schemaHint                { x.Def = v; return x }
func (x schemaHint) min(n int) schemaHint                { x.Min = &n; return x }
func (x schemaHint) max(n int) schemaHint                { x.Max = &n; return x }
func (x schemaHint) rng(lo, hi int) schemaHint           { return x.min(lo).max(hi) }
func (x schemaHint) enum(vals []any, t ...tr) schemaHint { x.Enum, x.EnumT = vals, t; return x }

func strs(v ...string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

// Shared hints of fields that appear in several types.
var (
	hName     = h("Name", "Name")
	hFileMode = h("Mode", "Rechte").d("Octal file mode, for example 0644.", "Oktale Dateirechte, zum Beispiel 0644.")
	hOwner    = h("Owner", "Besitzer").d("User name, root when empty.", "Benutzername, root wenn leer.")
	hGroup    = h("Group", "Gruppe").d("Group name, root when empty.", "Gruppenname, root wenn leer.")
	hCompare  = h("Operator", "Operator").enum(strs(api.CompareOps...), tr{"equals", "gleich"}, tr{"not equal", "ungleich"}, tr{"less than", "kleiner als"},
		tr{"less or equal", "kleiner gleich"}, tr{"greater than", "größer als"}, tr{"greater or equal", "größer gleich"}, tr{"contains", "enthält"}, tr{"matches (RE2)", "passt auf (RE2)"})
)

var schemaHints = map[string]map[string]schemaHint{
	api.TypeAgent: {
		"checkin_seconds":    h("Check in interval", "Check in Intervall").d("Seconds between two check ins of the agent, 30 to 86400.", "Sekunden zwischen zwei Check ins des Agenten, 30 bis 86400.").rng(30, 86400),
		"offline_lock_hours": h("Offline lock", "Sperre ohne Serverkontakt").d("Lock the device when the server was unreachable this many hours; 0 switches it off.", "Gerät sperren, wenn der Server so viele Stunden nicht erreichbar war; 0 schaltet es ab.").rng(0, 8760),
		"remote_shell":       h("Remote shell", "Remote Shell").d("Devices accept remote shell sessions from the console. Who may start them, root and four eyes are set under Settings, Remote shell.", "Geräte nehmen Remote Shell Sitzungen aus der Konsole an. Wer sie starten darf, root und Vier Augen stehen unter Einstellungen, Remote Shell."),
		"workload_control":   h("Workload control", "Container und VMs steuern").d("The console may start, stop and restart containers and VMs (Docker, Podman, LXC, Incus, Proxmox, libvirt) on devices. Off by default; the inventory is shown either way. Helpdesk access and four eyes are set under Settings, Approvals.", "Die Konsole darf Container und VMs (Docker, Podman, LXC, Incus, Proxmox, libvirt) auf Geräten starten, stoppen und neu starten. Standardmäßig aus; das Inventar wird immer angezeigt. Helpdesk Zugriff und Vier Augen stehen unter Einstellungen, Freigaben."),
	},
	api.TypeCompliance: {
		"level":                 h("Level", "Stufe").d("L1 is the baseline for every device, L2 adds strict checks.", "L1 ist die Basis für jedes Gerät, L2 ergänzt strenge Prüfungen.").enum([]any{1, 2}, tr{"L1 baseline", "L1 Basis"}, tr{"L2 strict", "L2 streng"}).sec("Policy", "Richtlinie"),
		"remediate":             h("Fix automatically", "Automatisch beheben").d("The agent fixes failing checks that have an automatic fix.", "Der Agent behebt fehlschlagende Prüfungen, für die es eine automatische Korrektur gibt.").sec("Policy", "Richtlinie"),
		"exclude":               h("Excluded checks", "Ausgenommene Prüfungen").d("Check IDs excluded on purpose; shown as excepted, never as passed.", "Prüf IDs, die bewusst ausgenommen sind; erscheinen als ausgenommen, nie als bestanden.").sec("Checks", "Prüfungen"),
		"advisory":              h("Advisory checks", "Nur informative Prüfungen").d("Reported, but not counted against compliance.", "Werden gemeldet, zählen aber nicht gegen die Konformität.").sec("Checks", "Prüfungen"),
		"grace_hours":           h("Grace period (hours)", "Karenzzeit (Stunden)").d("Time to fix failing checks before the device counts as non-compliant, 0 to 2160.", "Zeit zum Beheben, bevor das Gerät als nicht konform gilt, 0 bis 2160.").rng(0, 2160).sec("Escalation", "Eskalation"),
		"notify":                h("Notify", "Benachrichtigen").d("Call the compliance webhook when the grace period ends.", "Den Compliance Webhook aufrufen, wenn die Karenzzeit endet.").sec("Escalation", "Eskalation"),
		"lock_after_hours":      h("Lock after (hours)", "Sperren nach (Stunden)").d("Lock the device this long after it became non-compliant; 0 never locks. Not shorter than the grace period.", "Gerät so lange nach Verlust der Konformität sperren; 0 sperrt nie. Nicht kürzer als die Karenzzeit.").rng(0, 2160).sec("Escalation", "Eskalation"),
		"unlock_when_compliant": h("Unlock when compliant", "Entsperren bei Konformität").d("Lift an automatic lock once every counted check passes again.", "Eine automatische Sperre aufheben, sobald alle gezählten Prüfungen wieder bestehen.").sec("Escalation", "Eskalation"),
	},
	api.TypeUpdates: {
		"mode":                  h("Updates", "Updates").enum(strs("off", "security", "all"), tr{"Off", "Aus"}, tr{"Security only", "Nur Sicherheit"}, tr{"All", "Alle"}).sec("Schedule", "Zeitplan"),
		"window":                h("Time window", "Zeitfenster").d("Local time as HH:MM-HH:MM, for example 02:00-04:00.", "Lokale Zeit als HH:MM-HH:MM, zum Beispiel 02:00-04:00.").sec("Schedule", "Zeitplan"),
		"days":                  h("Weekdays", "Wochentage").d("Empty means every day.", "Leer bedeutet jeden Tag.").w("checkboxes").enum(strs("mon", "tue", "wed", "thu", "fri", "sat", "sun"), tr{"Mon", "Mo"}, tr{"Tue", "Di"}, tr{"Wed", "Mi"}, tr{"Thu", "Do"}, tr{"Fri", "Fr"}, tr{"Sat", "Sa"}, tr{"Sun", "So"}).sec("Schedule", "Zeitplan"),
		"reboot":                h("Reboot when required", "Neustart wenn nötig").d("Reboot inside the window after an update that needs it.", "Im Zeitfenster neu starten, wenn ein Update es verlangt.").sec("Reboot", "Neustart"),
		"reboot_notice_minutes": h("Reboot notice (minutes)", "Vorwarnung (Minuten)").d("Announce the reboot this long ahead, 5 when empty, at most 120.", "Den Neustart so lange vorher ankündigen, 5 wenn leer, höchstens 120.").rng(0, 120).sec("Reboot", "Neustart"),
		"reboot_max_defers":     h("Deferrals", "Aufschübe").d("How often a user may postpone the reboot, 0 to 5.", "Wie oft ein Nutzer den Neustart verschieben darf, 0 bis 5.").rng(0, 5).sec("Reboot", "Neustart"),
		"reboot_defer_minutes":  h("Deferral length (minutes)", "Dauer eines Aufschubs (Minuten)").d("15 to 480, 60 when empty.", "15 bis 480, 60 wenn leer.").max(480).sec("Reboot", "Neustart"),
		"hold":                  h("Held packages", "Zurückgehaltene Pakete").d("Packages that are never updated automatically.", "Pakete, die nie automatisch aktualisiert werden.").sec("Packages", "Pakete"),
		"autoremove":            h("Remove unused packages", "Unbenutzte Pakete entfernen").d("After each run, old kernels included.", "Nach jedem Lauf, auch alte Kernel.").sec("Packages", "Pakete"),
		"snap_refresh":          h("Snap refreshes", "Snap Aktualisierungen").d("Hold stops automatic refreshes, window moves them into the update window; empty leaves snapd alone.", "Anhalten stoppt automatische Aktualisierungen, Zeitfenster verlegt sie ins Updatefenster; leer lässt snapd unverändert.").enum(strs("hold", "window"), tr{"Hold", "Anhalten"}, tr{"In the window", "Im Zeitfenster"}).sec("Packages", "Pakete"),
		// R3-P
		"rules":             h("Rules per source", "Regeln je Quelle").d("When present they replace the mode: each source gets its own mode, window and ring.", "Wenn vorhanden, ersetzen sie den Modus: jede Quelle bekommt eigenen Modus, Zeitfenster und Ring.").sec("Sources", "Quellen"),
		"rules[].source":    h("Source", "Quelle").enum(strs(api.UpdateSources...), tr{"OS security updates", "Sicherheitsupdates des Systems"}, tr{"All OS updates", "Alle Updates des Systems"}, tr{"Third party repositories", "Drittanbieter Repositories"}, tr{"Flatpak (system)", "Flatpak (System)"}),
		"rules[].mode":      h("Mode", "Modus").d("Notify only reports pending updates; install installs them in the window.", "Melden zeigt nur ausstehende Updates; Installieren installiert sie im Zeitfenster.").enum(strs("off", "notify", "install"), tr{"Off", "Aus"}, tr{"Notify", "Melden"}, tr{"Install", "Installieren"}),
		"rules[].window":    h("Time window", "Zeitfenster").d("HH:MM-HH:MM; empty uses the window above.", "HH:MM-HH:MM; leer nutzt das Zeitfenster oben."),
		"rules[].days":      h("Weekdays", "Wochentage").d("Empty means every day.", "Leer bedeutet jeden Tag.").w("checkboxes").enum(strs("mon", "tue", "wed", "thu", "fri", "sat", "sun"), tr{"Mon", "Mo"}, tr{"Tue", "Di"}, tr{"Wed", "Mi"}, tr{"Thu", "Do"}, tr{"Fri", "Fr"}, tr{"Sat", "Sa"}, tr{"Sun", "So"}),
		"rules[].rings":     h("Follow update rings", "Updateringen folgen").d("Install once per wave of the device's update ring, not before.", "Einmal je Welle des Updaterings des Geräts installieren, nicht früher."),
		"rules[].repos":     h("Repositories", "Repositories").d("Third party only: dnf or zypper repo IDs, apt origins (glob). Empty is every third party repository.", "Nur Drittanbieter: dnf oder zypper Repo IDs, apt Origins (Glob). Leer bedeutet alle Drittanbieter Repositories."),
		"security_max_days": h("Security updates pending at most (days)", "Sicherheitsupdates höchstens ausstehend (Tage)").d("The check updates.security_age fails after this many days, 14 when empty.", "Die Prüfung updates.security_age schlägt nach so vielen Tagen fehl, 14 wenn leer.").rng(0, 365).sec("Sources", "Quellen"),
	},
	api.TypePackages: {
		"install": h("Install", "Installieren").d("Package names of the distribution.", "Paketnamen der Distribution."),
		"remove":  h("Remove", "Entfernen").d("Package names that must not be installed.", "Paketnamen, die nicht installiert sein dürfen."),
	},
	api.TypeServices: {
		"enable":  h("Enable", "Aktivieren").d("systemd units that are enabled and started, for example sshd.service.", "systemd Units, die aktiviert und gestartet werden, zum Beispiel sshd.service."),
		"disable": h("Disable", "Deaktivieren").d("systemd units that are stopped and disabled.", "systemd Units, die gestoppt und deaktiviert werden."),
	},
	api.TypeFiles: {
		"files":           h("Files", "Dateien"),
		"files[].path":    h("Path", "Pfad").d("Absolute path of the file.", "Absoluter Pfad der Datei."),
		"files[].content": h("Content", "Inhalt").w("code"),
		"files[].mode":    hFileMode,
		"files[].owner":   hOwner,
		"files[].group":   hGroup,
		"files[].template": h("Template", "Vorlage").d("Render the content per device: {{.Hostname}}, {{.ID}}, {{.Tenant}}, {{.PrimaryUser}}, {{.Tags}}, {{.Attributes.name}}; check it with the preview.",
			"Inhalt pro Gerät erzeugen: {{.Hostname}}, {{.ID}}, {{.Tenant}}, {{.PrimaryUser}}, {{.Tags}}, {{.Attributes.name}}; mit der Vorschau prüfen."),
	},
	api.TypeFirewall: {
		"enforce":      h("Enforce", "Durchsetzen").d("Deny inbound traffic except the listed ports.", "Eingehenden Verkehr bis auf die genannten Ports blockieren."),
		"allow":        h("Allowed ports", "Erlaubte Ports").d("Port and protocol, for example 22/tcp or 60000:61000/udp.", "Port und Protokoll, zum Beispiel 22/tcp oder 60000:61000/udp."),
		"rules":        h("Rules by source", "Regeln nach Quelle").d("Allow a port only from these networks.", "Einen Port nur aus diesen Netzen erlauben."),
		"rules[].port": h("Port", "Port").d("As in allowed ports, for example 22/tcp.", "Wie bei erlaubten Ports, zum Beispiel 22/tcp."),
		"rules[].from": h("From", "Von").d("Address or network in CIDR, for example 10.0.0.0/8.", "Adresse oder Netz als CIDR, zum Beispiel 10.0.0.0/8."),
		"zones": h("Zones", "Zonen").d("Open ports only for traffic from these interfaces or networks. firewalld uses the zone of that name; ufw and nftables match interface and source per rule.",
			"Ports nur für Verkehr aus diesen Schnittstellen oder Netzen öffnen. firewalld nutzt die Zone mit diesem Namen; ufw und nftables prüfen Schnittstelle und Quelle je Regel.").sec("Zones", "Zonen"),
		"zones[].name":       h("Zone", "Zone").d("Lower case, for example internal or trusted.", "Kleinbuchstaben, zum Beispiel internal oder trusted."),
		"zones[].interfaces": h("Interfaces", "Schnittstellen").d("For example wg0.", "Zum Beispiel wg0."),
		"zones[].sources":    h("Sources", "Quellen").d("Addresses or networks in CIDR.", "Adressen oder Netze als CIDR."),
		"zones[].allow":      h("Allowed ports", "Erlaubte Ports").d("As in allowed ports.", "Wie bei erlaubten Ports."),
		"outbound":           h("Outbound", "Ausgehend").d("Traffic the device sends; empty leaves it alone.", "Verkehr, den das Gerät sendet; leer lässt ihn unverändert.").sec("Outbound", "Ausgehend"),
		"outbound.policy": h("Default", "Standard").d("Deny allows only the rules below plus DNS, DHCP, NTP and the LiMDM server.", "Blockieren erlaubt nur die Regeln unten sowie DNS, DHCP, NTP und den LiMDM Server.").
			enum(strs("allow", "deny"), tr{"Allow", "Erlauben"}, tr{"Deny", "Blockieren"}),
		"outbound.allow":        h("Allowed destinations", "Erlaubte Ziele"),
		"outbound.allow[].to":   h("To", "Nach").d("Address or network in CIDR, empty is any.", "Adresse oder Netz als CIDR, leer ist beliebig."),
		"outbound.allow[].port": h("Port", "Port").d("For example 443/tcp, empty is any.", "Zum Beispiel 443/tcp, leer ist beliebig."),
		"template": h("Template", "Vorlage").d("Render every rule per device, for example {{.Attributes.office_net}}; check it with the preview.",
			"Jede Regel pro Gerät erzeugen, zum Beispiel {{.Attributes.office_net}}; mit der Vorschau prüfen.").sec("Template", "Vorlage"),
		"keep": h("Exceptions", "Ausnahmen").d("Rules LiMDM did not add that stay on the device, as set in the firewall tab of a device. Nothing removes them.",
			"Regeln, die nicht von LiMDM stammen und auf dem Gerät bleiben, wie im Firewall Reiter eines Geräts gesetzt. Nichts entfernt sie.").sec("Exceptions", "Ausnahmen"),
		"remove": h("Rules to remove", "Zu entfernende Regeln").d("Rules LiMDM did not add that the agent deletes whenever it finds them, also after a reboot, as set with Discard in the firewall tab of a device. Rules of LiMDM, of container, VPN and protection tools and exceptions are never removed.",
			"Regeln, die nicht von LiMDM stammen und die der Agent löscht, wann immer er sie findet, auch nach einem Neustart, wie mit Verwerfen im Firewall Reiter eines Geräts gesetzt. Regeln von LiMDM, von Container, VPN und Schutzwerkzeugen und Ausnahmen werden nie entfernt.").sec("Exceptions", "Ausnahmen"),
	},
	api.TypeOSVersion: {
		"min": h("Minimum versions", "Mindestversionen").d("os-release ID as key (ubuntu, debian, fedora) and the minimum VERSION_ID as value.", "os-release ID als Schlüssel (ubuntu, debian, fedora) und die Mindest VERSION_ID als Wert."),
	},
	api.TypeScreenLock: {
		"idle_seconds":    h("Lock after idle (seconds)", "Sperren nach Leerlauf (Sekunden)").d("30 to 3600.", "30 bis 3600.").rng(30, 3600),
		"hide_users":      h("Hide user list", "Benutzerliste ausblenden").d("The login screen asks for the user name instead of listing users.", "Der Anmeldebildschirm fragt den Benutzernamen ab, statt Nutzer aufzulisten."),
		"allow_autologin": h("Allow automatic login", "Automatische Anmeldung erlauben").d("Off switches automatic login off.", "Aus schaltet die automatische Anmeldung ab.").def(true),
	},
	api.TypeLogin: {
		"enabled":             h("Enabled", "Aktiv").d("Off switches desktop login with the identity provider off, for example for servers.", "Aus schaltet die Desktop Anmeldung mit dem Identitätsanbieter ab, zum Beispiel für Server.").def(true).sec("Provider", "Anbieter"),
		"issuer":              h("Issuer", "Aussteller").d("https URL of the OIDC provider, for example https://accounts.google.com.", "https URL des OIDC Anbieters, zum Beispiel https://accounts.google.com.").sec("Provider", "Anbieter"),
		"client_id":           h("Client ID", "Client ID").sec("Provider", "Anbieter"),
		"client_secret":       h("Client secret", "Client Secret").d("Stored sealed on the server.", "Wird versiegelt auf dem Server gespeichert.").w("secret").sec("Provider", "Anbieter"),
		"allowed_domain":      h("Allowed domain", "Erlaubte Domain").d("Google hd claim or email domain of the company accounts.", "Google hd Claim oder E-Mail Domain der Firmenkonten.").sec("Provider", "Anbieter"),
		"mode":                h("Mode", "Modus").d("Session binds the account once and confirms it in the session; login asks for SSO at the login screen.", "Sitzung bindet das Konto einmal und bestätigt es in der Sitzung; Anmeldung verlangt SSO am Anmeldebildschirm.").enum(strs("session", "login"), tr{"Session", "Sitzung"}, tr{"Login", "Anmeldung"}).def("session").sec("Policy", "Richtlinie"),
		"local_password":      h("Local password", "Lokales Passwort").d("Login mode: the password typed at an SSO login becomes the local password.", "Anmeldemodus: das bei einer SSO Anmeldung eingegebene Passwort wird zum lokalen Passwort.").sec("Policy", "Richtlinie"),
		"reverify_hours":      h("Confirm again after (hours)", "Erneut bestätigen nach (Stunden)").d("720 when empty.", "720 wenn leer.").max(8760).sec("Policy", "Richtlinie"),
		"grace_hours":         h("Grace period (hours)", "Karenzzeit (Stunden)").d("Session mode: 168 when empty, at most 2160.", "Sitzungsmodus: 168 wenn leer, höchstens 2160.").max(2160).sec("Policy", "Richtlinie"),
		"offline_grace_hours": h("Offline grace (hours)", "Karenz ohne Serverkontakt (Stunden)").d("Login mode: extra time while the server is unreachable, 0 to 720.", "Anmeldemodus: zusätzliche Zeit ohne Serverkontakt, 0 bis 720.").rng(0, 720).sec("Policy", "Richtlinie"),
	},
	api.TypePrivacy: {
		"network_info":    h("Network details", "Netzwerkdetails").d("Collect IP addresses, routes and DNS.", "IP Adressen, Routen und DNS erfassen."),
		"logged_in_users": h("Signed in users", "Angemeldete Nutzer").d("Collect the user names of active sessions.", "Benutzernamen aktiver Sitzungen erfassen."),
	},
	api.TypeRepositories: {
		"repositories":                   h("Repositories", "Paketquellen"),
		"repositories[].name":            hName,
		"repositories[].family":          h("Family", "Familie").enum(strs("debian", "fedora", "suse"), tr{"Debian, Ubuntu", "Debian, Ubuntu"}, tr{"Fedora, RHEL", "Fedora, RHEL"}, tr{"SUSE", "SUSE"}),
		"repositories[].url":             h("URL", "URL").d("https URL of the repository.", "https URL der Paketquelle."),
		"repositories[].suites":          h("Suites", "Suites").d("apt only, for example stable.", "Nur apt, zum Beispiel stable."),
		"repositories[].components":      h("Components", "Komponenten").d("apt only, for example main.", "Nur apt, zum Beispiel main."),
		"repositories[].key":             h("Signing key", "Signaturschlüssel").d("ASCII armored public key.", "ASCII armored öffentlicher Schlüssel.").w("code"),
		"repositories[].key_file":        h("Key file", "Schlüsseldatei").d("Or a keyring already on the device.", "Oder ein Schlüsselbund, der schon auf dem Gerät liegt."),
		"repositories[].signed_metadata": h("Signed metadata", "Signierte Metadaten").d("The repository signs its metadata, not each package.", "Die Quelle signiert ihre Metadaten, nicht jedes Paket."),
		"disable":                        h("Disable sources", "Quellen abschalten").d("Source files on the device to switch off.", "Quelldateien auf dem Gerät, die abgeschaltet werden."),
	},
	api.TypeCertificates: {
		"certificates":        h("Certificates", "Zertifikate"),
		"certificates[].name": hName,
		"certificates[].pem":  h("Certificate (PEM)", "Zertifikat (PEM)").w("code"),
	},
	api.TypeSysctl: {
		"settings": h("Parameters", "Parameter").d("sysctl key and value, for example net.ipv4.ip_forward = 0.", "sysctl Schlüssel und Wert, zum Beispiel net.ipv4.ip_forward = 0."),
	},
	api.TypeKernelModules: {
		"block": h("Blocked modules", "Gesperrte Module").d("Kernel modules that must not load, for example usb-storage.", "Kernelmodule, die nicht geladen werden dürfen, zum Beispiel usb-storage."),
	},
	api.TypeSSH: {
		"options": h("Options", "Optionen").d("sshd_config option and value; options that weaken the baseline are refused.", "sshd_config Option und Wert; Optionen, die die Basis schwächen, werden abgelehnt."),
	},
	api.TypeBanner: {
		"issue": h("Before login", "Vor der Anmeldung").d("Shown on the console, over SSH and on the login screen.", "Erscheint an der Konsole, über SSH und am Anmeldebildschirm.").w("textarea"),
		"motd":  h("After login", "Nach der Anmeldung").d("Message of the day.", "Nachricht des Tages.").w("textarea"),
	},
	api.TypeDNS: {
		"servers": h("Servers", "Server").d("IP addresses of the DNS servers.", "IP Adressen der DNS Server."),
		"domains": h("Search domains", "Suchdomains"),
		"dnssec":  h("DNSSEC", "DNSSEC").d("Validate DNS answers.", "DNS Antworten validieren."),
	},
	api.TypeNTP: {
		"servers": h("Servers", "Server").d("Host names or addresses of time servers.", "Hostnamen oder Adressen der Zeitserver."),
	},
	api.TypeProxy: {
		"http":     h("HTTP proxy", "HTTP Proxy").d("For example http://proxy.example.com:3128.", "Zum Beispiel http://proxy.example.com:3128."),
		"https":    h("HTTPS proxy", "HTTPS Proxy"),
		"no_proxy": h("Exceptions", "Ausnahmen").d("Comma separated hosts and domains without proxy.", "Hosts und Domains ohne Proxy, durch Kommas getrennt."),
	},
	api.TypeFlatpak: {
		"remotes":            h("Remotes", "Remotes"),
		"remotes[].name":     hName,
		"remotes[].url":      h("URL", "URL").d(".flatpakrepo file or repository URL.", ".flatpakrepo Datei oder URL der Quelle."),
		"remotes[].scope":    h("Installation", "Installation").enum(strs("system", "user"), tr{"System", "System"}, tr{"Every user", "Jeder Nutzer"}),
		"remotes[].disabled": h("Disabled", "Abgeschaltet").d("Keep the remote but switch it off.", "Remote behalten, aber abschalten."),
		"install":            h("Install", "Installieren").d("Flatpak application IDs, for example org.mozilla.firefox.", "Flatpak Anwendungs IDs, zum Beispiel org.mozilla.firefox."),
		"remove":             h("Remove", "Entfernen"),
	},
	api.TypeScripts: {
		"scripts":                   h("Scripts", "Skripte"),
		"scripts[].name":            hName,
		"scripts[].interval_hours":  h("Interval (hours)", "Intervall (Stunden)").d("1 to 720; empty with a schedule.", "1 bis 720; leer bei einem Zeitplan.").rng(1, 720),
		"scripts[].body":            h("Script", "Skript").d("Runs as root; start with a shebang such as #!/bin/sh.", "Läuft als root; mit einem Shebang wie #!/bin/sh beginnen.").w("code"),
		"scripts[].params":          h("Environment", "Umgebung").d("Environment variables for the script.", "Umgebungsvariablen für das Skript."),
		"scripts[].timeout_minutes": h("Timeout (minutes)", "Zeitlimit (Minuten)").d("1 to 240, 30 when empty.", "1 bis 240, 30 wenn leer.").max(240),
		"scripts[].schedule": h("Schedule", "Zeitplan").d("Fixed local times instead of the interval (leave the interval empty); at most one run per slot, a missed slot runs once at the next chance.",
			"Feste lokale Zeiten statt Intervall (das Feld Intervall leer lassen); höchstens ein Lauf je Zeitpunkt, ein verpasster läuft einmal bei nächster Gelegenheit."),
		"scripts[].schedule.times": h("Times", "Uhrzeiten").d("HH:MM in the device's local time, up to 24.", "HH:MM in lokaler Zeit des Geräts, bis zu 24."),
		"scripts[].schedule.days": h("Weekdays", "Wochentage").d("Empty means every day.", "Leer bedeutet jeden Tag.").w("checkboxes").enum(strs("mon", "tue", "wed", "thu", "fri", "sat", "sun"),
			tr{"Mon", "Mo"}, tr{"Tue", "Di"}, tr{"Wed", "Mi"}, tr{"Thu", "Do"}, tr{"Fri", "Fr"}, tr{"Sat", "Sa"}, tr{"Sun", "So"}),
		"scripts[].schedule.jitter_minutes": h("Jitter (minutes)", "Streuung (Minuten)").d("A fixed delay per device, 0 to 120, so the fleet does not start at once.", "Feste Verzögerung pro Gerät, 0 bis 120, damit nicht alle Geräte gleichzeitig starten.").rng(0, 120),
		"scripts[].run_on_change":           h("Run on change", "Bei Änderung ausführen").d("Also run once whenever the script, its environment or timeout change.", "Zusätzlich einmal ausführen, wenn sich Skript, Umgebung oder Zeitlimit ändern."),
	},
	api.TypeDiskEncryption: {
		"escrow":            h("Escrow recovery keys", "Wiederherstellungsschlüssel hinterlegen").d("Every LUKS volume needs a recovery key stored on the server.", "Jedes LUKS Volume braucht einen auf dem Server hinterlegten Schlüssel."),
		"rotate_after_view": h("Rotate after view", "Nach Ansicht erneuern").d("Replace a key once someone viewed it in the console.", "Einen Schlüssel ersetzen, sobald ihn jemand in der Konsole angesehen hat."),
		"require_all":       h("Every volume", "Jedes Volume").d("Every local volume must be on LUKS, not only the root file system.", "Jedes lokale Volume muss auf LUKS liegen, nicht nur das Wurzeldateisystem."),
		"exclude":           h("Exempt mount points", "Ausgenommene Mountpoints").d("For example /boot.", "Zum Beispiel /boot."),
		"tpm2":              h("TPM", "TPM").d("Also unlock the volumes with the TPM.", "Die Volumes zusätzlich mit dem TPM entsperren."),
		"tpm2.pcrs":         h("PCRs", "PCRs").d("PCR indexes the key is sealed to; 7 (Secure Boot state) when empty.", "PCR Indizes, an die der Schlüssel gebunden ist; 7 (Secure Boot Zustand) wenn leer."),
		"tpm2.pin":          h("PIN at boot", "PIN beim Start").d("The user sets it with limdm-agent recovery-key.", "Der Nutzer setzt sie mit limdm-agent recovery-key."),
		"tpm2.require":      h("Require TPM binding", "TPM Bindung verlangen").d("The compliance check fails while a volume is not bound.", "Die Compliance Prüfung schlägt fehl, solange ein Volume nicht gebunden ist."),
	},
	api.TypePolkit: {
		"rules":                     h("Rules", "Regeln"),
		"rules[].name":              hName,
		"rules[].actions":           h("Actions", "Aktionen").d("polkit action IDs; prefix.* matches a namespace.", "polkit Aktions IDs; prefix.* trifft einen Namensraum."),
		"rules[].groups":            h("Groups", "Gruppen").d("Empty means every user.", "Leer bedeutet jeder Nutzer."),
		"rules[].result":            h("Result", "Ergebnis").enum(strs("yes", "no", "auth_self", "auth_self_keep", "auth_admin", "auth_admin_keep"), tr{"Allow", "Erlauben"}, tr{"Deny", "Verbieten"}, tr{"Own password", "Eigenes Passwort"}, tr{"Own password, remembered", "Eigenes Passwort, gemerkt"}, tr{"Admin password", "Admin Passwort"}, tr{"Admin password, remembered", "Admin Passwort, gemerkt"}),
		"rules[].local_active_only": h("Local active session only", "Nur lokale aktive Sitzung"),
	},
	api.TypeSudo: {
		"rules":              h("Rules", "Regeln"),
		"rules[].name":       hName,
		"rules[].principals": h("Users and groups", "Nutzer und Gruppen").d("User names or %group.", "Benutzernamen oder %gruppe."),
		"rules[].run_as":     h("Run as", "Ausführen als").d("Empty means root.", "Leer bedeutet root."),
		"rules[].commands":   h("Commands", "Befehle").d("Absolute paths with optional arguments, or ALL.", "Absolute Pfade mit optionalen Argumenten, oder ALL."),
		"rules[].nopasswd":   h("Without password", "Ohne Passwort"),
		"timestamp_timeout":  h("Password remembered (minutes)", "Passwort gemerkt (Minuten)").d("0 asks every time, at most 60.", "0 fragt jedes Mal, höchstens 60.").rng(0, 60),
	},
	api.TypeSoftwareStore: {
		"restrict_flathub":     h("Only catalog apps", "Nur Katalog Apps").d("Remotes marked catalog only offer only catalog apps.", "Remotes mit Nur Katalog bieten nur Apps aus dem Katalog an."),
		"stores_read_only":     h("Stores read only", "Stores nur lesend").d("GNOME Software and KDE Discover cannot install.", "GNOME Software und KDE Discover können nicht installieren."),
		"only_managed_remotes": h("Only managed remotes", "Nur verwaltete Remotes").d("Every other Flatpak remote is switched off.", "Jedes andere Flatpak Remote wird abgeschaltet."),
	},
	api.TypeBootloader: {
		"superuser":       h("Superuser", "Superuser").d("GRUB user name.", "GRUB Benutzername."),
		"password":        h("Password", "Passwort").d("Hashed by the console when saved; never stored in clear.", "Wird beim Speichern gehasht und nie im Klartext gespeichert.").w("secret"),
		"password_pbkdf2": h("Password hash", "Passwort Hash").d("grub.pbkdf2 hash; filled in from the password.", "grub.pbkdf2 Hash; wird aus dem Passwort gefüllt."),
		"unrestricted":    h("Boot without password", "Start ohne Passwort").d("Booting the default entries needs no password, editing does.", "Das Starten der Standardeinträge braucht kein Passwort, das Bearbeiten schon."),
	},
	api.TypeNetwork: {
		"profiles":                                          h("Profiles", "Profile"),
		"profiles[].name":                                   hName,
		"profiles[].type":                                   h("Type", "Typ").enum(strs("wifi", "ethernet", "wireguard", "openvpn"), tr{"WLAN", "WLAN"}, tr{"Wired", "Kabel"}, tr{"WireGuard", "WireGuard"}, tr{"OpenVPN", "OpenVPN"}),
		"profiles[].auto_connect":                           h("Connect automatically", "Automatisch verbinden").d("Not for OpenVPN.", "Nicht für OpenVPN.").def(true),
		"profiles[].ssid":                                   h("SSID", "SSID").d("WLAN only.", "Nur WLAN."),
		"profiles[].hidden":                                 h("Hidden network", "Verstecktes Netz"),
		"profiles[].security":                               h("Security", "Sicherheit").d("WLAN: WPA2 or WPA3, personal or enterprise; wired: 802.1X.", "WLAN: WPA2 oder WPA3, Personal oder Enterprise; Kabel: 802.1X.").enum(strs("wpa2-personal", "wpa3-personal", "wpa2-enterprise", "wpa3-enterprise", "802.1x"), tr{"WPA2 Personal", "WPA2 Personal"}, tr{"WPA3 Personal", "WPA3 Personal"}, tr{"WPA2 Enterprise", "WPA2 Enterprise"}, tr{"WPA3 Enterprise", "WPA3 Enterprise"}, tr{"802.1X", "802.1X"}),
		"profiles[].psk":                                    h("Passphrase", "Passphrase").d("WLAN personal; shown masked, kept when unchanged.", "WLAN Personal; maskiert angezeigt, bleibt unverändert erhalten.").w("secret"),
		"profiles[].eap":                                    h("802.1X", "802.1X"),
		"profiles[].eap.method":                             h("Method", "Methode").enum(strs("tls", "peap", "ttls"), tr{"EAP-TLS (device certificate)", "EAP-TLS (Gerätezertifikat)"}, tr{"PEAP", "PEAP"}, tr{"TTLS", "TTLS"}),
		"profiles[].eap.identity":                           h("Identity", "Identität").d("TLS: the device certificate's common name when empty.", "TLS: der Common Name des Gerätezertifikats, wenn leer."),
		"profiles[].eap.anonymous_identity":                 h("Anonymous identity", "Anonyme Identität").d("Outer identity for PEAP and TTLS.", "Äußere Identität für PEAP und TTLS."),
		"profiles[].eap.password":                           h("Password", "Passwort").d("PEAP and TTLS; empty asks the user.", "PEAP und TTLS; leer fragt den Nutzer.").w("secret"),
		"profiles[].eap.phase2":                             h("Inner method", "Innere Methode").enum(strs("mschapv2", "pap"), tr{"MSCHAPv2", "MSCHAPv2"}, tr{"PAP (TTLS only)", "PAP (nur TTLS)"}),
		"profiles[].eap.ca_cert":                            h("CA certificate (PEM)", "CA Zertifikat (PEM)").d("Checks the RADIUS server.", "Prüft den RADIUS Server.").w("code"),
		"profiles[].eap.server_domain":                      h("Server domain", "Serverdomain").d("Expected domain of the RADIUS certificate.", "Erwartete Domain des RADIUS Zertifikats."),
		"profiles[].wireguard":                              h("WireGuard", "WireGuard"),
		"profiles[].wireguard.interface":                    h("Interface", "Schnittstelle").d("wg- plus the profile name when empty.", "wg- plus Profilname, wenn leer."),
		"profiles[].wireguard.addresses":                    h("Addresses", "Adressen").d("CIDR, for example 10.8.0.2/32.", "CIDR, zum Beispiel 10.8.0.2/32."),
		"profiles[].wireguard.dns":                          h("DNS", "DNS"),
		"profiles[].wireguard.mtu":                          h("MTU", "MTU").d("1280 to 9000, empty for the default.", "1280 bis 9000, leer für den Standard.").max(9000),
		"profiles[].wireguard.peers":                        h("Peers", "Gegenstellen"),
		"profiles[].wireguard.peers[].public_key":           h("Public key", "Öffentlicher Schlüssel"),
		"profiles[].wireguard.peers[].preshared_key":        h("Preshared key", "Preshared Key").w("secret"),
		"profiles[].wireguard.peers[].endpoint":             h("Endpoint", "Endpunkt").d("host:port", "host:port"),
		"profiles[].wireguard.peers[].allowed_ips":          h("Allowed IPs", "Erlaubte IPs").d("CIDR networks routed through the tunnel.", "CIDR Netze, die durch den Tunnel gehen."),
		"profiles[].wireguard.peers[].persistent_keepalive": h("Keepalive (seconds)", "Keepalive (Sekunden)").rng(0, 65535),
		"profiles[].openvpn":                                h("OpenVPN", "OpenVPN"),
		"profiles[].openvpn.content":                        h("Configuration (.ovpn)", "OpenVPN Profil (.ovpn)").d("Inline certificates and keys allowed.", "Eingebettete Zertifikate und Schlüssel erlaubt.").w("code"),
	},
	api.TypePrinters: {
		"printers":               h("Printers", "Drucker"),
		"printers[].name":        h("Queue name", "Warteschlange").d("After the limdm- prefix.", "Nach dem Präfix limdm-."),
		"printers[].uri":         h("URI", "URI").d("ipp:// or ipps://; socket:// and lpd:// only with a PPD.", "ipp:// oder ipps://; socket:// und lpd:// nur mit PPD."),
		"printers[].ppd":         h("PPD model", "PPD Modell").d("As lpinfo -m lists it; empty uses driverless IPP Everywhere.", "Wie lpinfo -m es listet; leer nutzt treiberloses IPP Everywhere."),
		"printers[].package":     h("Driver package", "Treiberpaket").d("Installed first, provides the PPD.", "Wird zuerst installiert und liefert das PPD."),
		"printers[].location":    h("Location", "Standort"),
		"printers[].description": h("Display name", "Anzeigename"),
		"printers[].default":     h("Default printer", "Standarddrucker"),
		"printers[].duplex":      h("Duplex", "Duplex").enum(strs("one-sided", "two-sided-long-edge", "two-sided-short-edge"), tr{"One sided", "Einseitig"}, tr{"Long edge", "Lange Kante"}, tr{"Short edge", "Kurze Kante"}),
		"printers[].paper_size":  h("Paper size", "Papierformat").d("For example A4 or Letter.", "Zum Beispiel A4 oder Letter."),
		"install_cups":           h("Install CUPS", "CUPS installieren").d("Where it is missing; otherwise such devices are skipped.", "Wo es fehlt; sonst werden solche Geräte übersprungen."),
	},
	api.TypeCustomChecks: {
		"checks":                      h("Checks", "Prüfungen"),
		"checks[].id":                 h("ID", "ID").d("custom. followed by a name, for example custom.no_uid0.", "custom. gefolgt von einem Namen, zum Beispiel custom.no_uid0."),
		"checks[].title":              h("Title", "Titel"),
		"checks[].severity":           h("Severity", "Schwere").enum(strs("low", "medium", "high", "critical"), tr{"Low", "Niedrig"}, tr{"Medium", "Mittel"}, tr{"High", "Hoch"}, tr{"Critical", "Kritisch"}),
		"checks[].level":              h("Level", "Stufe").enum([]any{1, 2}, tr{"L1", "L1"}, tr{"L2", "L2"}),
		"checks[].refs":               h("References", "Referenzen"),
		"checks[].refs.cis":           h("CIS", "CIS"),
		"checks[].refs.cis_benchmark": h("CIS benchmark", "CIS Benchmark"),
		"checks[].refs.bsi":           h("BSI IT-Grundschutz", "BSI IT-Grundschutz"),
		"checks[].refs.iso":           h("ISO 27001", "ISO 27001"),
		"checks[].query":              h("osquery test", "osquery Test").d("Use exactly one test per check.", "Genau einen Test je Prüfung verwenden."),
		"checks[].query.sql":          h("SQL", "SQL").d("Read only osquery query.", "Nur lesende osquery Abfrage.").w("code"),
		"checks[].query.expect":       h("Passes when", "Besteht wenn").enum(strs("rows", "no_rows", "compare"), tr{"Rows", "Zeilen"}, tr{"No rows", "Keine Zeilen"}, tr{"Compare", "Vergleich"}),
		"checks[].query.column":       h("Column", "Spalte"),
		"checks[].query.op":           hCompare,
		"checks[].query.value":        h("Value", "Wert"),
		"checks[].file":               h("File test", "Dateitest"),
		"checks[].file.path":          h("Path", "Pfad"),
		"checks[].file.state":         h("State", "Zustand").enum(strs("present", "absent"), tr{"Present", "Vorhanden"}, tr{"Absent", "Fehlt"}),
		"checks[].file.max_mode":      h("Maximum mode", "Höchstrechte").d("Octal, for example 0644.", "Oktal, zum Beispiel 0644."),
		"checks[].file.owner":         h("Owner", "Besitzer"),
		"checks[].file.group":         h("Group", "Gruppe"),
		"checks[].file.contains":      h("Contains (RE2)", "Enthält (RE2)"),
		"checks[].file.not_contains":  h("Does not contain (RE2)", "Enthält nicht (RE2)"),
		"checks[].sysctl":             h("sysctl test", "sysctl Test"),
		"checks[].sysctl.key":         h("Key", "Schlüssel"),
		"checks[].sysctl.op":          hCompare,
		"checks[].sysctl.value":       h("Value", "Wert"),
		"checks[].package":            h("Package test", "Pakettest"),
		"checks[].package.name":       h("Package", "Paket"),
		"checks[].package.state":      h("State", "Zustand").enum(strs("installed", "absent"), tr{"Installed", "Installiert"}, tr{"Absent", "Fehlt"}),
		"checks[].service":            h("Service test", "Diensttest"),
		"checks[].service.name":       h("Unit", "Unit"),
		"checks[].service.state":      h("State", "Zustand").enum(strs("active", "inactive"), tr{"Active", "Aktiv"}, tr{"Inactive", "Inaktiv"}),
		"checks[].service.enabled":    h("Enabled", "Aktiviert").d("Checked only when set.", "Wird nur geprüft, wenn gesetzt."),
	},
	api.TypeDconf: {
		"settings": h("Settings", "Einstellungen").d("dconf path and GVariant value, for example /org/gnome/desktop/session/idle-delay = uint32 300.", "dconf Pfad und GVariant Wert, zum Beispiel /org/gnome/desktop/session/idle-delay = uint32 300."),
		"locks":    h("Locked keys", "Gesperrte Schlüssel").d("Users cannot change these keys.", "Nutzer können diese Schlüssel nicht ändern."),
	},
	api.TypeLocalUsers: {
		"users":                   h("Accounts", "Konten"),
		"users[].name":            h("User name", "Benutzername"),
		"users[].uid":             h("UID", "UID").d("Only used when the account is created; 1000 to 60000 or empty.", "Nur beim Anlegen genutzt; 1000 bis 60000 oder leer.").max(60000),
		"users[].full_name":       h("Full name", "Voller Name"),
		"users[].groups":          h("Groups", "Gruppen").d("Supplementary groups, must exist.", "Zusätzliche Gruppen, müssen existieren."),
		"users[].shell":           h("Shell", "Shell").d("/bin/bash when empty.", "/bin/bash wenn leer."),
		"users[].locked":          h("Locked", "Gesperrt"),
		"users[].authorized_keys": h("SSH keys", "SSH Schlüssel").d("Public keys, one per entry, no options.", "Öffentliche Schlüssel, einer je Eintrag, ohne Optionen."),
	},
	api.TypeArtifacts: {
		"artifacts":          h("Uploads", "Uploads").d("Packages, scripts and files from the package repository.", "Pakete, Skripte und Dateien aus dem Paketspeicher."),
		"artifacts[].sha256": h("SHA-256", "SHA-256").d("Of the upload, as the package list shows it.", "Des Uploads, wie die Paketliste ihn zeigt."),
		"artifacts[].name":   hName,
		"artifacts[].kind":   h("Kind", "Art").enum(strs(api.ArtifactKinds...)),
		"artifacts[].size":   h("Size (bytes)", "Größe (Bytes)").min(0),
		"artifacts[].path":   h("Path", "Pfad").d("Files only: where it is written.", "Nur Dateien: wohin sie geschrieben wird."),
		"artifacts[].mode":   h("Mode", "Rechte").d("Files only: octal, 0644 when empty.", "Nur Dateien: oktal, 0644 wenn leer."),
	},
}

// schemaLang is the language of a schema answer: the lang parameter of the
// console app, else the request's language.
func schemaLang(r *http.Request) string {
	if l := r.URL.Query().Get("lang"); knownLang(l) {
		return l
	}
	return requestLang(r)
}

// annotateSchema adds the form hints of typ to its payload schema, in lang.
func annotateSchema(sch map[string]any, typ, lang string) {
	pick := func(t tr) string {
		if lang == "de" {
			return t[1]
		}
		return translate(lang, t[0]) // the other languages translate the English text
	}
	for path, x := range schemaHints[typ] {
		node := schemaAt(sch, path)
		if node == nil {
			continue
		}
		if x.T[0] != "" {
			node["title"] = pick(x.T)
		}
		if x.D[0] != "" {
			node["description"] = pick(x.D)
		}
		if x.Sec[0] != "" {
			node["x-section"] = pick(x.Sec)
		}
		target := node
		if x.Widget != "" {
			node["x-widget"] = x.Widget
			if x.Widget == "secret" {
				node["x-secret"] = true
			}
			if x.Widget == "checkboxes" { // choices of the list items
				target, _ = node["items"].(map[string]any)
			}
		}
		if x.Enum != nil && target != nil {
			target["enum"] = x.Enum
			titles := make([]string, len(x.EnumT))
			for i, t := range x.EnumT {
				titles[i] = pick(t)
			}
			if len(titles) > 0 {
				target["x-enumTitles"] = titles
			}
		}
		if x.Min != nil {
			node["minimum"] = *x.Min
		}
		if x.Max != nil {
			node["maximum"] = *x.Max
		}
		if x.Def != nil {
			node["default"] = x.Def
		}
	}
}

// schemaAt finds the schema of a field path such as "profiles[].eap.psk".
func schemaAt(sch map[string]any, path string) map[string]any {
	cur := sch
	for _, part := range strings.Split(path, ".") {
		name, list := strings.CutSuffix(part, "[]")
		props, _ := cur["properties"].(map[string]any)
		next, _ := props[name].(map[string]any)
		if next == nil {
			return nil
		}
		if list {
			if next, _ = next["items"].(map[string]any); next == nil {
				return nil
			}
		}
		cur = next
	}
	return cur
}
