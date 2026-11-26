package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Device certificates for EAP-TLS (802.1X). The network CA is a root of its
// own next to the device CA (network-ca.crt and network-ca.key in the CA
// directory): the device CA is limited to path length zero, and a separate
// root keeps the agents' mTLS certificates out of network authentication.
// Agents generate the key and send a CSR over mTLS; the server sets subject
// and SANs itself. Retiring or wiping a device revokes its certificates; the
// CRL is served to the RADIUS server at an authenticated URL.

const (
	networkCertTTL = 90 * 24 * time.Hour // agents renew 30 days before expiry
	crlValidity    = 7 * 24 * time.Hour
)

func init() { typeLabels[api.TypeNetwork] = "Network profiles" }

func loadOrCreateNetworkCA(dir string) (*deviceCA, error) {
	return loadRoot(KeyProvider{}, dir, kindNetCA, "LiMDM Network CA")
}

var certHostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$`)

// netCertRow is one issued network certificate.
type netCertRow struct {
	Serial, DeviceID, Hostname, Subject, SANs string
	NotBefore, NotAfter                       time.Time
	RevokedAt                                 *time.Time
	Reason                                    string
}

// State is valid, expired or revoked.
func (c netCertRow) State() string {
	switch {
	case c.RevokedAt != nil:
		return "revoked"
	case time.Now().After(c.NotAfter):
		return "expired"
	}
	return "valid"
}

// signNetworkCSR issues an EAP-TLS client certificate. Template: CN is the
// device ID, SANs are the host name (DNS), urn:limdm:device:<id> (URI) and
// the primary user's email when known. The CSR contributes only its key.
func (ca *deviceCA) signNetworkCSR(csrPEM, deviceID, hostname, email string) (string, netCertRow, error) {
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return "", netCertRow{}, err
	}
	uri, err := url.Parse("urn:limdm:device:" + deviceID)
	if err != nil {
		return "", netCertRow{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: deviceID, Organization: []string{"LiMDM network"}},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(networkCertTTL),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{uri},
	}
	sans := []string{"URI:" + uri.String()}
	if certHostRe.MatchString(hostname) {
		tmpl.DNSNames = []string{hostname}
		sans = append(sans, "DNS:"+hostname)
	}
	if a, err := mail.ParseAddress(email); err == nil && a.Address == email {
		tmpl.EmailAddresses = []string{email}
		sans = append(sans, "email:"+email)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return "", netCertRow{}, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), netCertRow{
		Serial: tmpl.SerialNumber.Text(16), DeviceID: deviceID, Subject: "CN=" + deviceID + ",O=LiMDM network",
		SANs: strings.Join(sans, ", "), NotBefore: tmpl.NotBefore, NotAfter: tmpl.NotAfter}, nil
}

// networkCert issues the EAP-TLS certificate to a device whose declarations
// contain an EAP-TLS profile.
func (s *Server) networkCert(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(deviceKey).(string)
	var req api.RenewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "bad request")
		return
	}
	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.failAPI(w, err)
		return
	}
	defer tx.Rollback(ctx)
	res, err := resolveDevice(ctx, tx, id)
	if err != nil {
		s.failAPI(w, err)
		return
	}
	if pol, _ := api.Compose(res.Decls); !api.NeedsDeviceCert(pol.Extra.Network) {
		problem(w, http.StatusForbidden, "no EAP-TLS network profile applies to this device")
		return
	}
	var host, email string
	if err := tx.QueryRow(ctx, `SELECT d.hostname, COALESCE(u.email, d.users->0->>'email', '')
		FROM devices d LEFT JOIN dir_users u ON u.id=d.primary_user_id AND u.active WHERE d.id=$1`, id).Scan(&host, &email); err != nil {
		s.failAPI(w, err)
		return
	}
	cert, row, err := s.netCA.signNetworkCSR(req.CSR, id, host, email)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid certificate signing request")
		return
	}
	if _, err := tx.Exec(ctx, `INSERT INTO network_certs(serial, device_id, subject, sans, not_before, not_after, ca) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		row.Serial, id, row.Subject, row.SANs, row.NotBefore, row.NotAfter, s.keyStates()[kindNetCA].Active); err != nil {
		s.failAPI(w, err)
		return
	}
	if err := audit(ctx, tx, "device:"+id, "network.cert_issue", id, row.Serial+" "+row.SANs); err != nil {
		s.failAPI(w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.failAPI(w, err)
		return
	}
	writeJSON(w, api.EnrollResponse{DeviceID: id, Cert: cert})
}

// revokeNetworkCerts revokes every valid network certificate of a device.
func revokeNetworkCerts(ctx context.Context, tx pgx.Tx, deviceID, reason string) error {
	_, err := tx.Exec(ctx, `UPDATE network_certs SET revoked_at=now(), revoke_reason=$2
		WHERE device_id=$1 AND revoked_at IS NULL AND not_after > now()`, deviceID, reason)
	return err
}

// networkCRL is the PEM CRL of the network CA, during a rotation followed by
// the CRL of the retiring CA (both list every revoked serial; serials are
// random 127 bit numbers). Expired certificates drop out.
func (s *Server) networkCRL(ctx context.Context) ([]byte, error) {
	rows, err := s.db.Query(ctx, `SELECT serial, revoked_at FROM network_certs WHERE revoked_at IS NOT NULL AND not_after > now() ORDER BY revoked_at`)
	if err != nil {
		return nil, err
	}
	var entries []x509.RevocationListEntry
	for rows.Next() {
		var sn string
		var at time.Time
		if err := rows.Scan(&sn, &at); err != nil {
			return nil, err
		}
		n, ok := new(big.Int).SetString(sn, 16)
		if !ok {
			return nil, fmt.Errorf("network certificate serial %q", sn)
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: at, ReasonCode: 5}) // cessationOfOperation
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	var out []byte
	for _, ca := range []*deviceCA{s.netCA, s.kr.netPrev} {
		if ca == nil {
			continue
		}
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(now.UnixNano()),
			ThisUpdate: now, NextUpdate: now.Add(crlValidity), RevokedCertificateEntries: entries}, ca.cert, ca.key)
		if err != nil {
			return nil, err
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})...)
	}
	return out, nil
}

func (s *Server) networkRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /network", s.page(s.adminOrAuditor(s.unscoped(s.networkPage)))) // every device's certificates
	mux.HandleFunc("POST /network/crl-token", s.page(s.networkCRLToken))
	mux.HandleFunc("GET /network/ca.pem", s.page(func(w http.ResponseWriter, r *http.Request, _ session) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="limdm-network-ca.pem"`)
		w.Write(s.netCA.pem)
		if s.kr.netPrev != nil { // RADIUS trusts both during a rotation
			w.Write(s.kr.netPrev.pem)
		}
	}))
	mux.HandleFunc("GET /network/crl.pem", s.networkCRLDownload)
}

// networkCRLDownload serves the CRL to a console session or to a client with
// the CRL bearer token (the RADIUS server's fetch job).
func (s *Server) networkCRLDownload(w http.ResponseWriter, r *http.Request) {
	serve := func(w http.ResponseWriter, r *http.Request, _ session) {
		crl, err := s.networkCRL(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Header().Set("Content-Disposition", `attachment; filename="limdm-network.crl.pem"`)
		w.Write(crl)
	}
	tok, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !bearer {
		s.page(serve)(w, r)
		return
	}
	if s.limit.over("crl:"+rateKey(r), 20, 5*time.Minute) {
		http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
		return
	}
	var stored struct {
		Hash string `json:"token_sha256"`
	}
	var raw []byte
	err := s.db.QueryRow(r.Context(), `SELECT value FROM settings WHERE key='network_crl'`).Scan(&raw)
	if err == nil {
		err = json.Unmarshal(raw, &stored)
	}
	if err != nil || stored.Hash == "" || subtle.ConstantTimeCompare([]byte(fmt.Sprintf("%x", sha(tok))), []byte(stored.Hash)) != 1 {
		s.limit.allow("crl:"+rateKey(r), 20, 5*time.Minute) // counts the failure
		w.Header().Set("WWW-Authenticate", `Bearer realm="limdm-crl", error="invalid_token"`)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	serve(w, r, session{})
}

func (s *Server) networkCRLToken(w http.ResponseWriter, r *http.Request, sess session) {
	tok := "lmc_" + randToken(32)
	doc, _ := json.Marshal(map[string]string{"token_sha256": fmt.Sprintf("%x", sha(tok))})
	err := s.auditAction(r.Context(), sess.Email, "network.crl_token", "network_crl", "token rotated", func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `INSERT INTO settings(key, value) VALUES ('network_crl', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, string(doc))
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.notify(notice{Type: "network.crl_token", Severity: "warning", Title: "Network CRL token rotated",
		Text: sess.Email + " rotated the bearer token for network CRL downloads; RADIUS servers need the new token.", URL: s.cfg.PublicURL + "/network"})
	s.renderNetwork(w, r, sess, tok)
}

func (s *Server) networkPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderNetwork(w, r, sess, "")
}

func (s *Server) renderNetwork(w http.ResponseWriter, r *http.Request, sess session, token string) {
	certs, err := s.networkCerts(r.Context(), "")
	if err != nil {
		s.fail(w, err)
		return
	}
	var tokenSet bool
	if err := s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM settings WHERE key='network_crl')`).Scan(&tokenSet); err != nil {
		s.fail(w, err)
		return
	}
	sum := sha256.Sum256(s.netCA.cert.Raw)
	s.render(w, r, sess, "network", map[string]any{"Certs": certs, "Token": token, "TokenSet": tokenSet,
		"CRLURL": strings.TrimSuffix(s.cfg.PublicURL, "/") + "/network/crl.pem", "CAFingerprint": hex.EncodeToString(sum[:]),
		"CASubject": s.netCA.cert.Subject.String(), "CANotAfter": s.netCA.cert.NotAfter})
}

// networkCerts lists issued certificates, newest first: of one device, or
// the latest 500 of the fleet.
func (s *Server) networkCerts(ctx context.Context, deviceID string) ([]netCertRow, error) {
	rows, err := s.db.Query(ctx, `SELECT c.serial, c.device_id, COALESCE(d.hostname, ''), c.subject, c.sans, c.not_before, c.not_after, c.revoked_at, c.revoke_reason
		FROM network_certs c LEFT JOIN devices d ON d.id=c.device_id
		WHERE $1='' OR c.device_id=$1 ORDER BY c.not_before DESC LIMIT 500`, deviceID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (netCertRow, error) {
		var c netCertRow
		return c, row.Scan(&c.Serial, &c.DeviceID, &c.Hostname, &c.Subject, &c.SANs, &c.NotBefore, &c.NotAfter, &c.RevokedAt, &c.Reason)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return out, err
}
