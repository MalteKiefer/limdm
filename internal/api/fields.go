package api

import (
	"reflect"
	"strings"
)

// Field is one JSON field of a declaration payload; the tests check every
// field against the decoder and the JSON schema (schema_test.go). Path uses
// dots for nested objects and [] for list elements, e.g. "rules[].actions".
type Field struct {
	Path, Kind string
}

// payloadShapes are the Go values each declaration payload decodes into
// (the same types apply decodes with; anonymous ones are repeated here).
// TestPayloadShapes checks them against the decoder and the examples.
var payloadShapes = map[string]any{
	TypeAgent: agentPayload{}, TypeCompliance: Compliance{}, TypeUpdates: Updates{}, TypePackages: Packages{},
	TypeServices: Services{}, TypeFiles: filesPayload{}, TypeFirewall: Firewall{}, TypeOSVersion: osPayload{},
	TypeScreenLock: screenLockPayload{}, TypePrivacy: Privacy{},
	TypeLogin: struct {
		Login
		Enabled *bool `json:"enabled"`
	}{},
	TypeRepositories: struct {
		Repositories []Repository `json:"repositories"`
		Disable      []string     `json:"disable,omitempty"`
	}{},
	TypeCertificates: struct {
		Certificates []Certificate `json:"certificates"`
	}{},
	TypeSysctl: struct {
		Settings map[string]string `json:"settings"`
	}{},
	TypeKernelModules: struct {
		Block []string `json:"block"`
	}{},
	TypeSSH: struct {
		Options map[string]string `json:"options"`
	}{},
	TypeBanner: Banner{}, TypeDNS: DNS{}, TypeNTP: NTP{}, TypeProxy: Proxy{}, TypeFlatpak: Flatpak{},
	TypeScripts: struct {
		Scripts []Script `json:"scripts"`
	}{},
	TypeDiskEncryption: DiskEncryption{},
	TypePolkit: struct {
		Rules []PolkitRule `json:"rules"`
	}{},
	TypeSudo: Sudo{}, TypeSoftwareStore: SoftwareStore{},
	TypeBootloader: struct {
		Bootloader
		Password string `json:"password,omitempty"` // plain, hashed by the console on save (PrepareBootloader)
	}{},
	TypeNetwork: networkPayload{}, TypePrinters: Printers{}, TypeCustomChecks: customChecksPayload{}, TypeDconf: Dconf{},
	TypeLocalUsers: struct {
		Users []LocalUser `json:"users"`
	}{},
}

// PayloadFields lists the JSON fields of a declaration type, in struct order.
func PayloadFields(typ string) []Field {
	v, ok := payloadShapes[typ]
	if !ok {
		return nil
	}
	var out []Field
	walkFields(reflect.TypeOf(v), "", &out, 0)
	return out
}

func walkFields(t reflect.Type, prefix string, out *[]Field, depth int) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || depth > 4 {
		return
	}
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" || (!f.IsExported() && !f.Anonymous) {
			continue
		}
		if f.Anonymous && name == "" { // embedded: its fields belong to this object
			walkFields(f.Type, prefix, out, depth)
			continue
		}
		if name == "" {
			name = f.Name
		}
		path := prefix + name
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		*out = append(*out, Field{Path: path, Kind: kindName(ft)})
		switch {
		case ft.Kind() == reflect.Struct:
			walkFields(ft, path+".", out, depth+1)
		case ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct:
			walkFields(ft.Elem(), path+"[].", out, depth+1)
		}
	}
}

// kindName describes a Go type in JSON terms.
func kindName(t reflect.Type) string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return "text"
	case reflect.Bool:
		return "true or false"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Struct {
			return "list of objects"
		}
		return "list of " + kindName(t.Elem())
	case reflect.Map:
		return "object of " + kindName(t.Elem())
	case reflect.Struct:
		return "object"
	}
	return t.Kind().String()
}
