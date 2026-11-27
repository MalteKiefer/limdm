package server

import (
	"encoding/json"
	"slices"

	"github.com/maltekiefer/limdm/internal/api"
)

// com.limdm.logging on the server: labels and form hints, and the refusal
// on personal devices.

func init() {
	typeLabels[api.TypeLogging] = "Log collection"
	typeInfo[api.TypeLogging] = struct{ Desc, Anchor string }{"Ships journal, container and file logs to the server, filtered and masked on the device.", "comlimdmlogging"}
	prios := make([]tr, len(api.LogPriorities))
	for i, p := range api.LogPriorities {
		prios[i] = tr{p, p}
	}
	src, flt, lim := [2]string{"Sources", "Quellen"}, [2]string{"Filter and masking", "Filter und Maskierung"}, [2]string{"Limits", "Grenzen"}
	schemaHints[api.TypeLogging] = map[string]schemaHint{
		"enabled": h("Collect logs", "Logs sammeln").d("Off by default. The agent never changes journald or Docker settings.", "Standardmäßig aus. Der Agent ändert nie Einstellungen von journald oder Docker.").sec("General", "Allgemein"),
		"allow_personal": h("Also on personal devices", "Auch auf privaten Geräten").d("Devices tagged personal or with the attribute ownership=personal collect only with this switch.",
			"Geräte mit dem Tag personal oder dem Attribut ownership=personal sammeln nur mit diesem Schalter.").sec("General", "Allgemein"),
		"journald":      h("systemd journal", "systemd Journal").sec(src[0], src[1]),
		"units":         h("Only these units", "Nur diese Units").d("Empty: all units. * matches any text.", "Leer: alle Units. * steht für beliebigen Text.").sec(src[0], src[1]),
		"exclude_units": h("Exclude units", "Units ausschließen").sec(src[0], src[1]),
		"min_priority": h("Minimum priority", "Mindestpriorität").d("Lines of this priority and more severe ones; default info.", "Zeilen dieser und schwererer Priorität; Standard info.").
			enum(strs(api.LogPriorities...), prios...).sec(src[0], src[1]),
		"containers":         h("Docker and Podman containers", "Docker und Podman Container").sec(src[0], src[1]),
		"container_names":    h("Only containers named", "Nur Container mit Namen").d("* matches any text. Without names, labels and projects every container.", "* steht für beliebigen Text. Ohne Namen, Labels und Projekte alle Container.").sec(src[0], src[1]),
		"container_labels":   h("Only containers with label", "Nur Container mit Label").d("key=value", "key=value").sec(src[0], src[1]),
		"compose_projects":   h("Only compose projects", "Nur Compose Projekte").sec(src[0], src[1]),
		"exclude_containers": h("Exclude containers", "Container ausschließen").sec(src[0], src[1]),
		"files":              h("Log files", "Logdateien").d("Absolute paths; rotation by renaming to .1 and truncation is followed.", "Absolute Pfade; Rotation durch Umbenennen nach .1 und Kürzen wird verfolgt.").sec(src[0], src[1]),
		"include":            h("Only lines matching", "Nur passende Zeilen").d("Regular expressions on the message.", "Reguläre Ausdrücke auf die Nachricht.").sec(flt[0], flt[1]),
		"exclude":            h("Drop lines matching", "Passende Zeilen verwerfen").d("Regular expressions on the message.", "Reguläre Ausdrücke auf die Nachricht.").sec(flt[0], flt[1]),
		"mask_builtin": h("Built in masking", "Eingebaute Maskierung").d("Passwords, tokens, Authorization headers, private keys, credentials in URLs.", "Passwörter, Tokens, Authorization Header, private Schlüssel, Zugangsdaten in URLs.").
			def(true).sec(flt[0], flt[1]),
		"mask":             h("Mask", "Maskieren").d("Regular expressions; matched text becomes ***.", "Reguläre Ausdrücke; der Treffer wird zu ***.").sec(flt[0], flt[1]),
		"lines_per_second": h("Lines per second", "Zeilen pro Sekunde").d("Average with bursts of ten seconds; default 20.", "Mittelwert mit Spitzen von zehn Sekunden; Standard 20.").rng(0, 1000).sec(lim[0], lim[1]),
		"mb_per_day":       h("MB per day", "MB pro Tag").d("Default 100.", "Standard 100.").rng(0, 10240).sec(lim[0], lim[1]),
		"buffer_mb":        h("Offline buffer (MB)", "Offline Puffer (MB)").d("On disk while the server is not reachable; the oldest lines go first. Default 32.", "Auf der Platte, solange der Server nicht erreichbar ist; die ältesten Zeilen gehen zuerst. Standard 32.").rng(0, 1024).sec(lim[0], lim[1]),
	}
}

// personalDevice reports devices marked personal (BYOD).
func personalDevice(v api.TemplateVars) bool {
	return slices.Contains(v.Tags, "personal") || v.Attributes["ownership"] == "personal"
}

// refuseLogging switches a logging payload off for a personal device
// unless it allows personal devices.
func refuseLogging(payload json.RawMessage, v api.TemplateVars) json.RawMessage {
	var l api.Logging
	if json.Unmarshal(payload, &l) != nil || !l.Enabled || l.AllowPersonal || !personalDevice(v) {
		return payload
	}
	l.Enabled = false
	b, _ := json.Marshal(l)
	return b
}
