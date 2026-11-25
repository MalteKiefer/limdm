package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image/png"
	"net/http"

	"github.com/maltekiefer/limdm/internal/api"
)

// Branding: company name and logo, shown in the console and by the desktop
// helper on devices. Only PNG is accepted: an SVG served from the console's
// origin could carry script.

const maxLogo = 256 << 10

// Version is set at build time and shown in the console.
var Version = "dev"

func validLogo(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if len(b) > maxLogo {
		return errors.New("logo: at most 256 KiB")
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return errors.New("logo: PNG file required")
	}
	if cfg.Width > 1024 || cfg.Height > 1024 || cfg.Width < 16 || cfg.Height < 16 {
		return errors.New("logo: 16 to 1024 pixels per side")
	}
	return nil
}

// branding returns what devices receive; computed when settings are activated.
func (s *Server) branding() api.Branding { return s.rt.Load().branding }

// computeBranding derives the branding and a hash that changes with name or logo.
func computeBranding(set Settings) api.Branding {
	if set.CompanyName == "" && len(set.Logo) == 0 {
		return api.Branding{}
	}
	h := sha256.New()
	h.Write([]byte(set.CompanyName))
	h.Write([]byte{0})
	h.Write(set.Logo)
	return api.Branding{Name: set.CompanyName, Logo: set.Logo, Hash: hex.EncodeToString(h.Sum(nil))[:16]}
}

func (s *Server) logo(w http.ResponseWriter, r *http.Request) {
	b := s.settings().Logo
	if len(b) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write(b)
}
