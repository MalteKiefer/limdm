package server

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/maltekiefer/limdm/internal/api"
)

// sourceTemplate builds a library item from a package source a device reports:
// mode "disable" switches the file off, mode "edit" turns all of its entries
// into managed sources and switches the original off.
func (s *Server) sourceTemplate(ctx context.Context, deviceID, file, mode string) (api.LibraryItem, error) {
	var raw []byte
	if err := s.db.QueryRow(ctx, `SELECT inventory FROM devices WHERE id=$1`, deviceID).Scan(&raw); err != nil {
		return api.LibraryItem{}, err
	}
	var inv api.Inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		return api.LibraryItem{}, err
	}
	var entries []api.Repo
	for _, r := range inv.Repos {
		if r.File == file {
			entries = append(entries, r)
		}
	}
	base := filepath.Base(file)
	if len(entries) == 0 || strings.HasPrefix(base, "limdm-") {
		return api.LibraryItem{}, errors.New("unknown or managed source")
	}
	type repoT struct {
		Name       string `json:"name"`
		Family     string `json:"family"`
		URL        string `json:"url"`
		Suites     string `json:"suites,omitempty"`
		Components string `json:"components,omitempty"`
		Key        string `json:"key,omitempty"`
		KeyFile    string `json:"key_file,omitempty"`
	}
	payload := struct {
		Repositories []repoT  `json:"repositories"`
		Disable      []string `json:"disable"`
	}{Repositories: []repoT{}, Disable: []string{base}}
	it := api.LibraryItem{Type: api.TypeRepositories, Name: "Disable " + base,
		Description: "Switches off " + file + " on devices with this item."}
	if mode == "edit" {
		stem := strings.ToLower(nonName.ReplaceAllString(strings.TrimSuffix(base, filepath.Ext(base)), "-"))
		for i, r := range entries {
			name := stem
			if i > 0 {
				name = stem + "-" + string(rune('1'+i))
			}
			fam := "debian"
			if r.Type == "rpm" {
				fam = "fedora"
			}
			t := repoT{Name: strings.Trim(name, "-._"), Family: fam, URL: strings.Replace(r.URL, "http://", "https://", 1),
				Suites: r.Suites, Components: r.Components, KeyFile: r.KeyFile}
			if t.KeyFile == "" {
				t.Key = "-----BEGIN PGP PUBLIC KEY BLOCK----- paste the signing key, or set key_file"
			}
			payload.Repositories = append(payload.Repositories, t)
		}
		it.Name = "Source " + stem
		it.Description = "Managed copy of " + file + " (the original is switched off). Check the URL: https is required."
	}
	b, err := json.Marshal(payload)
	it.Payload = b
	return it, err
}

var nonName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// flatpakTemplate prefills a Flatpak library item from a remote a device
// reported: edit keeps it as it is (change the URL or scope), disable and
// enable switch it.
func (s *Server) flatpakTemplate(ctx context.Context, deviceID, name, inst, mode string) (api.LibraryItem, error) {
	var raw []byte
	if err := s.db.QueryRow(ctx, `SELECT inventory FROM devices WHERE id=$1`, deviceID).Scan(&raw); err != nil {
		return api.LibraryItem{}, err
	}
	var inv api.Inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		return api.LibraryItem{}, err
	}
	for _, r := range inv.FlatpakRemotes {
		if r.Name != name || r.Installation != inst {
			continue
		}
		scope := "system"
		if inst != "system" {
			scope = "user"
		}
		rem := api.FlatpakRemote{Name: r.Name, URL: strings.Replace(r.URL, "http://", "https://", 1), Scope: scope}
		it := api.LibraryItem{Type: api.TypeFlatpak, Name: "Flatpak remote " + r.Name,
			Description: "Flatpak remote " + r.Name + " (" + scope + " installation)."}
		switch mode {
		case "disable":
			rem.Disabled = true
			it.Name, it.Description = "Disable Flatpak remote "+r.Name, "Switches off the Flatpak remote "+r.Name+" ("+scope+" installation)."
		case "enable":
			it.Name, it.Description = "Enable Flatpak remote "+r.Name, "Switches on the Flatpak remote "+r.Name+" ("+scope+" installation)."
		}
		b, err := json.Marshal(api.Flatpak{Remotes: []api.FlatpakRemote{rem}, Install: []string{}, Remove: []string{}})
		it.Payload = b
		return it, err
	}
	return api.LibraryItem{}, errors.New("unknown remote")
}
