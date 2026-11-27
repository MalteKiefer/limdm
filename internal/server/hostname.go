package server

import (
	"context"
	"encoding/json"

	"github.com/maltekiefer/limdm/internal/api"
)

// com.limdm.hostname on the server: labels, help, form hints and the
// preview of the computed name for one device (from its last report).

func init() {
	typeLabels[api.TypeHostname] = "Host name"
	typeInfo[api.TypeHostname] = struct{ Desc, Anchor string }{"Host name from reverse DNS, DNS, the serial number, a template or a fixed name, with /etc/hosts and /etc/mailname.", "comlimdmhostname"}
	sources := []tr{{"Reverse DNS (PTR of the primary address)", "Reverse DNS (PTR der primären Adresse)"}, {"DNS name in the search domains", "DNS Name in den Suchdomains"},
		{"Serial number (DMI)", "Seriennummer (DMI)"}, {"Template", "Vorlage"}, {"Fixed name", "Fester Name"}}
	schemaHints[api.TypeHostname] = map[string]schemaHint{
		"source": h("Source", "Quelle").d("Where the name comes from. Changing the host name affects mail servers, Kerberos and AD joins and TLS names; check the preview first.",
			"Woher der Name kommt. Ein neuer Hostname betrifft Mailserver, Kerberos und AD Beitritte sowie TLS Namen; vorher die Vorschau prüfen.").enum(strs(api.HostnameSources...), sources...).sec("Name", "Name"),
		"name": h("Fixed name", "Fester Name").d("Short name or FQDN, for source fixed.", "Kurzname oder FQDN, für die Quelle fester Name.").sec("Name", "Name"),
		"template": h("Template", "Vorlage").d("For source template and as fallback: {{.Serial}}, {{.MAC}}, {{.Vendor}}, {{.Model}}, {{.Hostname}}, {{.ID}}, {{.Tenant}}, {{.Attributes.name}}, for example pc-{{lower .Serial}}.",
			"Für die Quelle Vorlage und als Ersatz: {{.Serial}}, {{.MAC}}, {{.Vendor}}, {{.Model}}, {{.Hostname}}, {{.ID}}, {{.Tenant}}, {{.Attributes.name}}, zum Beispiel pc-{{lower .Serial}}.").sec("Name", "Name"),
		"domain":     h("Domain", "Domain").d("FQDN = short name + domain; empty keeps the domain of rdns, dns or fixed.", "FQDN = Kurzname + Domain; leer übernimmt die Domain von rdns, dns oder festem Namen.").sec("Name", "Name"),
		"lowercase":  h("Lower case", "Kleinschreibung").d("On by default.", "Standardmäßig an.").def(true).sec("Rules", "Regeln"),
		"max_length": h("Maximum length", "Maximale Länge").d("Of the short name, 1 to 63; 0 means 63.", "Des Kurznamens, 1 bis 63; 0 bedeutet 63.").rng(0, 63).sec("Rules", "Regeln"),
		"fallback": h("Fallback", "Ersatz").d("When the source gives no usable name.", "Wenn die Quelle keinen brauchbaren Namen liefert.").
			enum(strs("keep", "template"), tr{"Keep the current name", "Aktuellen Namen behalten"}, tr{"Use the template", "Vorlage verwenden"}).sec("Rules", "Regeln"),
		"hosts":    h("Manage /etc/hosts", "/etc/hosts verwalten").d("Sets the line 127.0.1.1 FQDN short name; other lines stay.", "Setzt die Zeile 127.0.1.1 FQDN Kurzname; andere Zeilen bleiben.").sec("System files", "Systemdateien"),
		"mailname": h("Manage /etc/mailname", "/etc/mailname verwalten").d("Writes the FQDN where the file or an MTA exists; MTA settings are never changed.", "Schreibt den FQDN, wo die Datei oder ein MTA existiert; MTA Einstellungen werden nie geändert.").sec("System files", "Systemdateien"),
		"pretty":   h("Pretty name", "Anzeigename").d("Optional, shown by desktops (systemd only).", "Optional, von Desktops angezeigt (nur mit systemd).").sec("System files", "Systemdateien"),
	}
}

// hostnamePreview is the name com.limdm.hostname computes for a device from
// its last report: what the agent will set at its next check in.
type hostnamePreview struct {
	Current string            `json:"current"`
	Target  string            `json:"target,omitempty"`
	Source  string            `json:"source,omitempty"`
	Error   string            `json:"error,omitempty"`
	Facts   *api.HostnameInfo `json:"facts,omitempty"` // as reported: address, PTR, FQDN and the last result
	Serial  string            `json:"serial,omitempty"`
}

// previewHostname resolves a rendered hostname payload for the device.
func previewHostname(ctx context.Context, q querier, deviceID string, payload json.RawMessage) (*hostnamePreview, error) {
	var inv api.Inventory
	var raw []byte
	if err := q.QueryRow(ctx, `SELECT inventory FROM devices WHERE id = $1`, deviceID).Scan(&raw); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(raw, &inv)
	var h api.Hostname
	if err := json.Unmarshal(payload, &h); err != nil {
		return nil, err
	}
	p := &hostnamePreview{Current: inv.Hostname, Facts: inv.HostnameInfo, Serial: inv.Serial}
	f := api.HostnameFacts{Serial: inv.Serial}
	if inv.HostnameInfo != nil {
		f.PTR, f.FQDN = inv.HostnameInfo.PTR, inv.HostnameInfo.FQDN
	}
	_, fqdn, used, err := h.Resolve(f)
	p.Target, p.Source = fqdn, used
	if err != nil {
		p.Error = err.Error()
	}
	return p, nil
}
