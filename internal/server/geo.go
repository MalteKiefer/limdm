package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// Location of a device's public address. The agent port is never behind a
// proxy, so the TCP peer of a check in is the device's external address. The
// lookup goes to LIMDM_GEOIP_URL (default ipwho.is) only when the address
// changed; "off" disables it.
type Geo struct {
	IP          string `json:"ip"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	Region      string `json:"region,omitempty"`
	City        string `json:"city,omitempty"`
	ISP         string `json:"isp,omitempty"`
	ASN         int    `json:"asn,omitempty"`
}

func (g Geo) Place() string {
	switch {
	case g.City != "" && g.Country != "":
		return g.City + ", " + g.Country
	default:
		return g.Country
	}
}

// remoteIP is the public peer address of r, or "" for private and loopback peers.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

func publicAddr(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.IsGlobalUnicast() && !a.IsPrivate()
}

// locate looks up ip and stores the result. At most one lookup runs at a
// time; a skipped or failed lookup is retried after an hour.
func (s *Server) locate(id, ip string) {
	if s.cfg.GeoIPURL == "" || !publicAddr(ip) {
		return
	}
	select {
	case s.geoSem <- struct{}{}:
		defer func() { <-s.geoSem }()
	default:
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	g, err := s.lookupGeo(ctx, ip)
	if err != nil {
		s.log.Warn("geoip lookup", "err", err)
		_, _ = s.db.Exec(ctx, `UPDATE devices SET geo_at=now() WHERE id=$1`, id)
		return
	}
	doc, _ := json.Marshal(g)
	if _, err := s.db.Exec(ctx, `UPDATE devices SET geo=$2, geo_at=now() WHERE id=$1`, id, doc); err != nil {
		s.log.Warn("geoip store", "err", err)
	}
}

func (s *Server) lookupGeo(ctx context.Context, ip string) (Geo, error) {
	var resp struct {
		Success     bool   `json:"success"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		Connection  struct {
			ASN int    `json:"asn"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if err := getJSON(ctx, s.cfg.GeoIPURL+ip, &resp); err != nil {
		return Geo{}, err
	}
	if !resp.Success {
		return Geo{}, &geoError{resp.Message}
	}
	return Geo{IP: ip, Country: resp.Country, CountryCode: resp.CountryCode, Region: resp.Region, City: resp.City,
		ISP: resp.Connection.ISP, ASN: resp.Connection.ASN}, nil
}

type geoError struct{ msg string }

func (e *geoError) Error() string { return "geoip: " + e.msg }
