package server

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The console speaks English and German. Templates call {{t "English text"}};
// the English source text is the key, so a missing translation shows English.

const langCookie = "limdm_lang"

func translate(lang, s string) string {
	if lang == "de" {
		if v, ok := deCatalog[s]; ok {
			return v
		}
	}
	return s
}

// requestLang prefers the explicit choice (cookie), then Accept-Language.
func requestLang(r *http.Request) string {
	if r == nil {
		return "en"
	}
	if c, err := r.Cookie(langCookie); err == nil && (c.Value == "de" || c.Value == "en") {
		return c.Value
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		switch {
		case strings.HasPrefix(tag, "de"):
			return "de"
		case strings.HasPrefix(tag, "en"):
			return "en"
		}
	}
	return "en"
}

// setLang stores the choice and returns to the page the user came from
// (same origin paths only, so it cannot be used as an open redirect).
func (s *Server) setLang(w http.ResponseWriter, r *http.Request) {
	lang := r.PathValue("lang")
	if lang != "de" && lang != "en" {
		http.NotFound(w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: langCookie, Value: lang, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int((365 * 24 * time.Hour).Seconds())})
	back := "/"
	if ref, err := url.Parse(r.Referer()); err == nil && ref.Host == r.Host && strings.HasPrefix(ref.Path, "/") &&
		!strings.HasPrefix(ref.Path, "//") && !strings.HasPrefix(ref.Path, "/lang/") {
		back = ref.Path
		if ref.RawQuery != "" {
			back += "?" + ref.RawQuery
		}
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

var deCatalog = map[string]string{
	// navigation and layout
	"Overview": "Übersicht", "Devices": "Geräte", "Compliance": "Compliance", "Configuration": "Konfiguration",
	"Library": "Bibliothek", "Directory": "Verzeichnis", "Blueprints": "Blueprints", "Enrollment": "Registrierung",
	"Evidence": "Nachweise", "Audit log": "Audit Log", "Administration": "Administration", "Users": "Benutzer",
	"Settings": "Einstellungen", "Sign out": "Abmelden", "Main": "Hauptnavigation", "Language": "Sprache",
	"LiMDM": "LiMDM", "· LiMDM": "· LiMDM",
	"Overview · LiMDM": "Übersicht · LiMDM", "Devices · LiMDM": "Geräte · LiMDM", "Compliance · LiMDM": "Compliance · LiMDM",
	"Library · LiMDM": "Bibliothek · LiMDM", "Directory · LiMDM": "Verzeichnis · LiMDM", "Blueprints · LiMDM": "Blueprints · LiMDM",
	"Enrollment · LiMDM": "Registrierung · LiMDM", "Audit log · LiMDM": "Audit Log · LiMDM", "Users · LiMDM": "Benutzer · LiMDM",
	"Settings · LiMDM": "Einstellungen · LiMDM", "Sign in · LiMDM": "Anmelden · LiMDM",

	// roles
	"admin": "Admin", "helpdesk": "Helpdesk", "auditor": "Auditor", "user": "Benutzer", "agent": "Agent", "policy": "Richtlinie",
	"admin: everything · helpdesk: devices and commands except scripts · auditor: read only": "Admin: alles · Helpdesk: Geräte und Befehle außer Skripten · Auditor: nur lesen",

	// statuses
	"compliant": "konform", "non-compliant": "nicht konform", "in grace": "in Karenz", "stale": "veraltet", "pending": "ausstehend",
	"retired": "ausgemustert", "stale or pending": "veraltet oder ausstehend", "Compliant": "Konform", "Non-compliant": "Nicht konform",
	"Stale": "Veraltet", "Pending": "Ausstehend", "In grace period": "In Karenzzeit", "pass": "bestanden", "fail": "fehlgeschlagen",
	"exception": "Ausnahme", "n/a": "n. v.", "ok": "ok", "failed": "fehlgeschlagen", "queued": "wartend", "sent": "gesendet",
	"applied": "angewendet", "error": "Fehler", "unknown": "unbekannt", "skipped": "übersprungen", "active": "aktiv",
	"inactive": "inaktiv", "enabled": "aktiviert", "disabled": "deaktiviert", "configured": "konfiguriert", "not set": "nicht gesetzt",
	"none": "keine", "nothing": "nichts", "remediated": "behoben", "installed": "installiert", "unused": "ungenutzt",
	"default": "Standard", "default only": "nur Standard", "never": "nie", "just now": "gerade eben",
	"%d min ago": "vor %d Min.", "%d h ago": "vor %d Std.", "%d d ago": "vor %d Tagen",

	// actions
	"Sync now": "Jetzt synchronisieren", "Install all updates": "Alle Updates installieren", "Reboot in 1 minute": "Neustart in 1 Minute",
	"Shut down in 1 minute": "Herunterfahren in 1 Minute", "Lock device": "Gerät sperren", "Unlock device": "Gerät entsperren",
	"Run script": "Skript ausführen", "Run script…": "Skript ausführen…", "Actions": "Aktionen", "Action": "Aktion",
	"Send": "Senden", "Send command": "Befehl senden", "Save": "Speichern", "Delete": "Löschen", "Apply": "Anwenden",
	"Reset": "Zurücksetzen", "Filter": "Filtern", "Search": "Suchen", "New": "Neu", "Next": "Weiter", "Previous": "Zurück",
	"Create token": "Token erstellen", "Rotate token": "Token erneuern", "Save and sync": "Speichern und synchronisieren",
	"Sync Google now": "Google jetzt synchronisieren", "Save assignment": "Zuweisung speichern", "Save blueprint": "Blueprint speichern",
	"Save item": "Element speichern", "Save settings": "Einstellungen speichern", "Add user": "Benutzer hinzufügen",
	"Reset credentials": "Zugangsdaten zurücksetzen", "Delete blueprint": "Blueprint löschen", "Delete item": "Element löschen",
	"Retire device": "Gerät ausmustern", "Retire and revoke certificate": "Ausmustern und Zertifikat widerrufen",
	"Enroll device": "Gerät registrieren", "New blueprint": "Neuer Blueprint", "New item": "Neues Element", "New token": "Neues Token",

	// overview and charts
	"active devices": "aktive Geräte", "Evidence CSV": "Nachweis CSV", "Inventory CSV": "Inventar CSV", "Audit CSV": "Audit CSV",
	"% of active": "% der aktiven", "at least one failing check": "mindestens eine fehlgeschlagene Prüfung", "silent for": "still seit",
	"h": "Std.", "no report yet": "noch kein Bericht", "Fleet status": "Flottenstatus", "Compliance trend": "Compliance Verlauf",
	"daily, 30 days": "täglich, 30 Tage", "Most failing checks": "Häufigste Fehler", "All checks": "Alle Prüfungen",
	"Check": "Prüfung", "Checks": "Prüfungen", "Level": "Stufe", "Failing": "Fehlgeschlagen", "L": "S",
	"No failing checks across the fleet.": "Keine fehlgeschlagenen Prüfungen in der Flotte.", "Operating systems": "Betriebssysteme",
	"Recent activity": "Letzte Aktivität", "Last 7 days": "Letzte 7 Tage", "sampled every 15 minutes": "alle 15 Minuten erfasst",
	"Memory used": "Belegter Arbeitsspeicher", "Root filesystem used": "Belegung Root Dateisystem", "Load (1 min)": "Last (1 Min.)",

	// devices list
	"Search host, OS, ID, blueprint": "Host, OS, ID, Blueprint suchen", "Search devices": "Geräte suchen", "All": "Alle",
	"Device": "Gerät", "Status": "Status", "Last seen": "Zuletzt gesehen", "last seen": "zuletzt gesehen", "Blueprint": "Blueprint",
	"Operating system": "Betriebssystem", "Failing checks": "Fehlgeschlagene Prüfungen", "shown": "angezeigt", "of": "von",
	"No devices enrolled.": "Keine Geräte registriert.", "No devices match. Create an enrollment token to add the first one.": "Keine passenden Geräte. Erstelle ein Registrierungstoken, um das erste Gerät hinzuzufügen.",

	// device page
	"Device sections": "Gerätebereiche", "System": "System", "Hardware": "Hardware", "Disks": "Datenträger", "Network": "Netzwerk",
	"Accounts": "Konten", "Account": "Konto", "Packages": "Pakete", "Package sources": "Paketquellen", "History": "Verlauf",
	"Distribution": "Distribution", "Version": "Version", "Kernel": "Kernel", "Architecture": "Architektur", "Desktop": "Desktop",
	"Display manager": "Display Manager", "Booted": "Gestartet", "Enrolled": "Registriert", "enrolled": "registriert",
	"Certificate": "Zertifikat", "valid until": "gültig bis", "Device ID": "Geräte ID", "Primary user": "Hauptbenutzer",
	"Tags": "Tags", "comma separated, usable in blueprint conditions": "durch Komma getrennt, nutzbar in Blueprint Bedingungen",
	"e.g. laptops batch 12": "z. B. Laptops Charge 12", "from the directory; brings groups and department into blueprint rules": "aus dem Verzeichnis; bringt Gruppen und Abteilung in Blueprint Regeln",
	"Assignment": "Zuweisung", "Resolved configuration": "Aufgelöste Konfiguration", "No items match this device.": "Für dieses Gerät passen keine Elemente.",
	"evaluated": "ausgewertet", "via": "über", "Locked by compliance policy.": "Durch Compliance Richtlinie gesperrt.",
	"Logins are blocked until the device is compliant again or an admin unlocks it.": "Anmeldungen sind gesperrt, bis das Gerät wieder konform ist oder ein Admin es entsperrt.",
	"Failing compliance since": "Nicht konform seit", "; grace period": "; Karenzzeit", "ends": "endet", "ended": "beendet",
	"Vendor": "Hersteller", "Model": "Modell", "Serial number": "Seriennummer", "Firmware": "Firmware", "System board": "Mainboard",
	"Processor and memory": "Prozessor und Arbeitsspeicher", "CPU": "CPU", "Cores / threads": "Kerne / Threads", "cores,": "Kerne,",
	"threads": "Threads", "Memory": "Arbeitsspeicher", "Swap": "Swap", "swap": "Swap", "no swap": "kein Swap", "GB": "GB",
	"Size": "Größe", "Used": "Belegt", "Free": "Frei", "Usage": "Belegung", "Filesystem": "Dateisystem", "Mount point": "Einhängepunkt",
	"Encryption": "Verschlüsselung", "LUKS": "LUKS", "Volumes": "Volumes", "volumes,": "Volumes,", "disks": "Datenträger",
	"Root filesystem": "Root Dateisystem", "No disk data reported.": "Keine Datenträgerdaten gemeldet.", "No volume data reported.": "Keine Volumedaten gemeldet.",
	"Interface": "Schnittstelle", "MAC": "MAC", "Addresses": "Adressen", "collected only with privacy network_info": "nur mit Datenschutz Option network_info erfasst",
	"not collected (privacy)": "nicht erfasst (Datenschutz)", "Not collected on this device.": "Auf diesem Gerät nicht erfasst.",
	"login accounts": "Anmeldekonten", "Desktop users": "Desktop Benutzer", "Logged in now:": "Jetzt angemeldet:", "UID": "UID",
	"Shell": "Shell", "Rights": "Rechte", "No account data reported.": "Keine Kontodaten gemeldet.", "Source": "Quelle", "Suites": "Suites",
	"Signature": "Signatur", "pinned key": "fester Schlüssel", "global keyring": "globaler Schlüsselbund",
	"No package sources reported.": "Keine Paketquellen gemeldet.", "Filter packages": "Pakete filtern", "Filter by package name": "Nach Paketname filtern",
	"Package": "Paket", "Package pages": "Paketseiten", "Page": "Seite", "No matching packages.": "Keine passenden Pakete.",
	"inventory via": "Inventar über", "Control": "Kontrolle", "Framework": "Framework", "Detail": "Detail", "Identifier": "Bezeichner",
	"Type": "Typ", "Reasons": "Gründe", "No declarations.": "Keine Deklarationen.", "No report yet.": "Noch kein Bericht.",
	"Command": "Befehl", "By": "Von", "Time": "Zeit", "Output": "Ausgabe", "No commands sent.": "Keine Befehle gesendet.",
	"Script": "Skript", "runs as root, only if the device allows scripts": "läuft als root, nur wenn das Gerät Skripte erlaubt",
	"Revokes the client certificate immediately. The device can no longer check in; history is kept.": "Widerruft das Clientzertifikat sofort. Das Gerät kann sich nicht mehr melden; der Verlauf bleibt erhalten.",
	"Transport": "Transport", "mTLS, TLS 1.3 only": "mTLS, nur TLS 1.3", "Agent": "Agent", "Note": "Hinweis",
	"Nothing recorded yet.": "Noch nichts aufgezeichnet.", "No reports yet.": "Noch keine Berichte.", "Most failing": "Häufigste Fehler",
	"warn": "Warnung",

	// compliance page
	"BSI IT-Grundschutz · CIS · ISO/IEC 27001:2022": "BSI IT-Grundschutz · CIS · ISO/IEC 27001:2022", "Search checks": "Prüfungen suchen",
	"State": "Zustand", "All states": "Alle Zustände", "Passing": "Bestanden", "All levels": "Alle Stufen", "Level 1": "Stufe 1",
	"Level 2": "Stufe 2", "All frameworks": "Alle Frameworks", "Sort": "Sortieren", "Sort by ID": "Nach ID sortieren", "Title": "Titel",
	"Pass": "Bestanden", "Fail": "Fehler", "Exception": "Ausnahme", "Failing devices": "Betroffene Geräte",
	"Coverage by framework": "Abdeckung je Framework", "pass and fail summed over devices": "bestanden und fehlgeschlagen über alle Geräte",

	// library and blueprints
	"Reusable configuration items, assigned to devices through blueprints": "Wiederverwendbare Konfigurationselemente, über Blueprints Geräten zugewiesen",
	"The library is empty. Create the first item.":                         "Die Bibliothek ist leer. Lege das erste Element an.", "Name": "Name",
	"Description": "Beschreibung", "Used by": "Verwendet von", "used by": "verwendet von", "Not used by any blueprint.": "Von keinem Blueprint verwendet.",
	"Library item": "Bibliothekselement", "Item type": "Elementtyp", "JSON, validated strictly before saving": "JSON, vor dem Speichern streng geprüft",
	"Example": "Beispiel", "JSON": "JSON", "Uses": "Verwendungen",
	"Lists (packages, services, files, firewall rules, OS minimums) from several items are merged; for every other type the item evaluated last in the blueprint wins.": "Listen (Pakete, Dienste, Dateien, Firewallregeln, OS Mindestversionen) aus mehreren Elementen werden zusammengeführt; bei allen anderen Typen gewinnt das zuletzt ausgewertete Element im Blueprint.",
	"Assignment maps: which library items a device gets, under which conditions":                                                                                        "Zuweisungen: welche Bibliothekselemente ein Gerät unter welchen Bedingungen erhält",
	"Inherits from": "Erbt von", "Assignment map": "Zuweisungskarte", "evaluated top to bottom; in a condition the first matching branch wins": "von oben nach unten ausgewertet; in einer Bedingung gewinnt der erste passende Zweig",
	"The visual editor needs JavaScript; edit the map as JSON below.":   "Der visuelle Editor braucht JavaScript; bearbeite die Karte unten als JSON.",
	"Validated on save: items must exist, rules must use known fields.": "Beim Speichern geprüft: Elemente müssen existieren, Regeln bekannte Felder verwenden.",
	"Devices pick up changes at their next check in.":                   "Geräte übernehmen Änderungen beim nächsten Check in.",
	"Devices assigned to it fall back to default.":                      "Zugewiesene Geräte fallen auf den Standard zurück.", "Updated": "Geändert",
	"Software updates": "Software Updates", "Services": "Dienste", "Files": "Dateien", "Firewall": "Firewall",
	"OS versions": "OS Versionen", "Screen lock": "Bildschirmsperre", "Desktop login (OIDC)": "Desktop Anmeldung (OIDC)",
	"Privacy": "Datenschutz", "CA certificates": "CA Zertifikate", "Kernel parameters": "Kernelparameter",
	"Blocked kernel modules": "Gesperrte Kernelmodule", "SSH server options": "SSH Server Optionen", "Login banner": "Anmeldebanner",
	"DNS": "DNS", "Time servers": "Zeitserver", "Proxy": "Proxy", "Flatpak apps": "Flatpak Apps", "Recurring scripts": "Wiederkehrende Skripte",

	// directory
	"People": "Personen", "people": "Personen", "Groups": "Gruppen", "groups": "Gruppen", "Group": "Gruppe", "Members": "Mitglieder",
	"Department": "Abteilung", "Email": "Mailadresse", "Search people": "Personen suchen", "Search name, email, department": "Name, Mailadresse, Abteilung suchen",
	"No people yet.": "Noch keine Personen.", "No groups yet. Connect an identity provider below.": "Noch keine Gruppen. Verbinde unten einen Identity Provider.",
	"devices without an explicit blueprint get the blueprint of their primary user's group; lower priority wins": "Geräte ohne festen Blueprint erhalten den Blueprint der Gruppe ihres Hauptbenutzers; die niedrigere Priorität gewinnt",
	"Priority": "Priorität", "from SCIM or Google Workspace": "aus SCIM oder Google Workspace", "SCIM 2.0": "SCIM 2.0",
	"For Okta, Microsoft Entra ID, authentik and JumpCloud. Configure the app with this base URL and a bearer token.": "Für Okta, Microsoft Entra ID, authentik und JumpCloud. Richte die App mit dieser Basis URL und einem Bearer Token ein.",
	"Base URL": "Basis URL", "SCIM token": "SCIM Token", "set (stored as hash)": "gesetzt (als Hash gespeichert)",
	"New SCIM token created; the previous one stopped working.": "Neues SCIM Token erstellt; das bisherige ist ungültig.",
	"Google Workspace": "Google Workspace", "Service account key": "Dienstkontoschlüssel", "paste the JSON key file": "JSON Schlüsseldatei einfügen",
	"stored encrypted; paste a new JSON key to replace": "verschlüsselt gespeichert; neuen JSON Schlüssel einfügen zum Ersetzen",
	"Admin to impersonate":                              "Admin für Delegation", "Last sync": "Letzte Synchronisierung", "Syncs hourly once configured.": "Synchronisiert stündlich, sobald eingerichtet.",
	"Google sync: ": "Google Synchronisierung: ", "Google sync failed: ": "Google Synchronisierung fehlgeschlagen: ",
	"paste the service account JSON key file":                            "JSON Schlüsseldatei des Dienstkontos einfügen",
	"service account key and an admin email for delegation are required": "Dienstkontoschlüssel und Admin Mailadresse für die Delegation sind erforderlich",
	"jane.doe@example.com":                                               "erika.mustermann@example.com", "finance, berlin": "finanzen, berlin",

	// enrollment
	"One time tokens bind new devices to the device CA": "Einmaltokens binden neue Geräte an die Geräte CA", "Token": "Token",
	"Token created.": "Token erstellt.", "Active tokens": "Aktive Tokens", "No active tokens.": "Keine aktiven Tokens.", "Expires": "Läuft ab",
	"Uses left": "Verbleibende Nutzungen", "Created": "Erstellt", "Created by": "Erstellt von", "Valid for days": "Gültig für Tage",
	"Device CA fingerprint (SHA-256), pinned by the agent at enrollment:": "Fingerabdruck der Geräte CA (SHA 256), vom Agent bei der Registrierung fest hinterlegt:",
	"Agent endpoint": "Agent Endpunkt",

	// audit
	"Append only, hash chained": "Nur anhängend, per Hash verkettet", "latest 300 entries": "letzte 300 Einträge", "Full log as CSV": "Vollständiges Log als CSV",
	"Actor": "Akteur", "Target": "Ziel", "Hash chain verified end to end: the log is intact.": "Hash Kette vollständig geprüft: das Log ist unverändert.",
	"Integrity failure.": "Integritätsfehler.", "The hash chain breaks at entry": "Die Hash Kette bricht bei Eintrag",
	"; the log was modified outside LiMDM.": "; das Log wurde außerhalb von LiMDM verändert.",

	// users
	"Console access: OIDC identities and local accounts": "Konsolenzugang: OIDC Identitäten und lokale Konten", "Role": "Rolle",
	"Login": "Anmeldung", "Last sign in": "Letzte Anmeldung", "Local account": "Lokales Konto", "local (password + TOTP)": "lokal (Passwort + TOTP)",
	"OIDC (email)": "OIDC (Mailadresse)", "Email or local name": "Mailadresse oder lokaler Name", "Credentials created.": "Zugangsdaten erstellt.",
	"Local accounts get a generated password and TOTP secret.": "Lokale Konten erhalten ein generiertes Passwort und ein TOTP Geheimnis.",
	"Username": "Benutzername", "Password": "Passwort", "unknown role": "unbekannte Rolle", "enter a plain email address": "gib eine einfache Mailadresse ein",
	"local name: 2..32 lowercase letters, digits, dot, dash, underscore": "lokaler Name: 2 bis 32 Kleinbuchstaben, Ziffern, Punkt, Minus, Unterstrich",
	"only local accounts have credentials to reset":                      "nur lokale Konten haben Zugangsdaten zum Zurücksetzen",
	"you cannot demote or disable your own account":                      "du kannst dein eigenes Konto nicht herabstufen oder deaktivieren",

	// settings
	"Single sign on (OIDC)": "Single Sign On (OIDC)", "Issuer": "Issuer", "Client ID": "Client ID", "Client secret": "Client Secret",
	"stored encrypted; leave empty to keep": "verschlüsselt gespeichert; leer lassen zum Beibehalten", "remove the stored secret": "gespeichertes Secret entfernen",
	"Allowed domain": "Erlaubte Domain", "Google hd claim or email domain, optional": "Google hd Claim oder Maildomain, optional",
	"OIDC changes are checked against the provider before they take effect.": "OIDC Änderungen werden vor der Übernahme beim Provider geprüft.",
	"allow local accounts (password + TOTP)":                                 "lokale Konten erlauben (Passwort + TOTP)", "Access and monitoring": "Zugang und Überwachung",
	"Device counts as stale after (hours)": "Gerät gilt als veraltet nach (Stunden)", "Compliance webhook": "Compliance Webhook",
	"https URL receiving JSON when a device becomes non-compliant": "https URL, die JSON erhält, wenn ein Gerät nicht konform wird",
	"Webhook signing key": "Webhook Signaturschlüssel", "Public URL": "Öffentliche URL", "URL": "URL",
	"Database, listeners and keys stay in the server environment":                                          "Datenbank, Listener und Schlüssel bleiben in der Serverumgebung",
	"Settings saved and active.":                                                                           "Einstellungen gespeichert und aktiv.",
	"Local login can only be disabled when OIDC is configured and at least one OIDC administrator exists.": "Die lokale Anmeldung kann nur deaktiviert werden, wenn OIDC eingerichtet ist und mindestens ein OIDC Administrator existiert.",
	"You are signed in with a local account; sign in with OIDC before disabling local login.":              "Du bist mit einem lokalen Konto angemeldet; melde dich vor dem Deaktivieren der lokalen Anmeldung per OIDC an.",
	"none (server)": "keine (Server)",

	// login
	"Sign in": "Anmelden", "Device management console": "Konsole für Geräteverwaltung", "Continue with single sign on": "Weiter mit Single Sign On",
	"or local administrator": "oder lokaler Administrator", "Authenticator code": "Code aus Authenticator App", "Sign in failed.": "Anmeldung fehlgeschlagen.",
	"Local login is currently disabled in the settings.": "Die lokale Anmeldung ist in den Einstellungen deaktiviert.",
	"OIDC": "OIDC", "BSI": "BSI", "CIS": "CIS", "ISO 27001": "ISO 27001", "BSI IT-Grundschutz": "BSI IT-Grundschutz",
	"CIS Benchmark": "CIS Benchmark", "ISO/IEC 27001": "ISO/IEC 27001",
	"admin@example.com": "admin@example.com", "example.com": "example.com", "https://accounts.google.com": "https://accounts.google.com",
	"https://hooks.example.com/limdm":      "https://hooks.example.com/limdm",
	"one per line: username email [admin]": "eine Zeile je Konto: Benutzername Mailadresse [admin]",

	// device security
	"overview": "Übersicht", "hardware": "Hardware", "software": "Software", "compliance": "Compliance",
	"declarations": "Deklarationen", "commands": "Befehle",
	"Recovery key": "Wiederherstellungsschlüssel", "Recovery keys": "Wiederherstellungsschlüssel", "Back to device": "Zurück zum Gerät",
	"Enter this key at the disk unlock prompt instead of the passphrase. This view was recorded in the audit log.": "Gib diesen Schlüssel beim Entsperren der Festplatte statt der Passphrase ein. Diese Ansicht wurde im Audit Log festgehalten.",
	"Escrowed": "Hinterlegt", "Last viewed": "Zuletzt angezeigt", "Show key": "Schlüssel anzeigen", "Volume UUID": "Volume UUID",
	"LUKS, escrowed by the agent; every view is audited":                                                 "LUKS, vom Agent hinterlegt; jede Anzeige wird protokolliert",
	"No recovery key escrowed. Declare disk encryption recovery; the user is then asked on the desktop.": "Kein Wiederherstellungsschlüssel hinterlegt. Deklariere die Wiederherstellung der Festplattenverschlüsselung; der Benutzer wird dann am Desktop gefragt.",
	"The device replaces this key at its next check in; afterwards it no longer works.":                  "Das Gerät ersetzt diesen Schlüssel beim nächsten Check in; danach ist er ungültig.",
	"rotation pending": "Rotation ausstehend", "addresses only with privacy option network_info": "Adressen nur mit Datenschutz Option network_info",
	"No interfaces reported.": "Keine Schnittstellen gemeldet.",
	"managed":                 "verwaltet", "Edit": "Bearbeiten", "Disable": "Deaktivieren",
	"Branding": "Branding", "Company name": "Firmenname", "Logo": "Logo", "remove logo": "Logo entfernen",
	"shown in the console and in dialogs on devices": "angezeigt in der Konsole und in Dialogen auf den Geräten",
	"PNG, square, up to 256 KiB":                     "PNG, quadratisch, bis 256 KiB", "Boot loader password": "Bootloader Passwort",
	"Disk encryption recovery": "Wiederherstellung Festplattenverschlüsselung", "polkit rules": "polkit Regeln", "sudo rules": "sudo Regeln",
}
