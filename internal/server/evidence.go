package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Signed evidence: a JSON bundle with the current check results of every
// device in scope, the risk exceptions, the changes of a history window,
// the catalog and agent versions and the score, signed with the command key
// (Ed25519). `limdm-server evidence verify FILE` checks it offline. The PDF
// report (evidencepdf.go) is rendered from the same bundle and names its
// SHA-256 and signature. Both are exports: audited before and after with
// the SHA-256 of the file sent (streamExport).

const evidenceFormat = "limdm-evidence/1"

type evidenceDevice struct {
	ID             string            `json:"id"`
	Hostname       string            `json:"hostname"`
	LastSeen       *time.Time        `json:"last_seen"`
	AgentVersion   string            `json:"agent_version"`
	CatalogVersion string            `json:"catalog_version"`
	Checks         []api.CheckResult `json:"checks"`
}

type evidenceChange struct {
	DeviceID string    `json:"device_id"`
	CheckID  string    `json:"check_id"`
	Status   string    `json:"status"`
	Detail   string    `json:"detail"`
	At       time.Time `json:"at"`
	Catalog  string    `json:"catalog_version"`
}

// evidenceBundle is the signed payload.
type evidenceBundle struct {
	Format          string           `json:"format"`
	GeneratedAt     time.Time        `json:"generated_at"`
	GeneratedBy     string           `json:"generated_by"`
	Tenant          int64            `json:"tenant"` // 0: the global view
	WindowDays      int              `json:"window_days"`
	Score           float64          `json:"score"`
	Reporting       int              `json:"reporting"`
	Compliant       int              `json:"compliant"`
	NonCompliant    int              `json:"noncompliant"`
	Stale           int              `json:"stale"`
	Pending         int              `json:"pending"`
	Frameworks      []statsFramework `json:"frameworks"`
	CatalogVersions map[string]int   `json:"catalog_versions"` // devices per check catalog version
	AgentVersions   map[string]int   `json:"agent_versions"`   // devices per agent version
	Devices         []evidenceDevice `json:"devices"`
	Exceptions      []apiException   `json:"exceptions"`
	History         []statsDay       `json:"history"` // fleet history per day, global view only
	Changes         []evidenceChange `json:"changes"` // check result changes within the window
}

type evidenceSignature struct {
	Alg       string `json:"alg"`        // ed25519
	PublicKey string `json:"public_key"` // hex
	KeyID     string `json:"key_id"`     // SHA-256 of the public key, hex
	Value     string `json:"value"`      // hex signature of evidenceFormat + "\n" + the compact payload
}

// signedEvidence is the file: the payload exactly as signed, and the signature.
type signedEvidence struct {
	Payload   json.RawMessage   `json:"payload"`
	Signature evidenceSignature `json:"signature"`
}

func evidenceMessage(payload []byte) []byte {
	return append([]byte(evidenceFormat+"\n"), payload...)
}

func keyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// maxEvidenceChanges bounds the history window of one bundle.
const maxEvidenceChanges = 200000

// buildEvidence collects the bundle for the scope of sess.
func (s *Server) buildEvidence(ctx context.Context, sess session, days int) (evidenceBundle, error) {
	b := evidenceBundle{Format: evidenceFormat, GeneratedAt: time.Now().UTC().Truncate(time.Second), GeneratedBy: sess.Email, Tenant: sess.Tenant,
		WindowDays: days, CatalogVersions: map[string]int{}, AgentVersions: map[string]int{}, Devices: []evidenceDevice{}, History: []statsDay{}, Changes: []evidenceChange{}}
	fc, err := s.fleetComplianceFor(ctx, sess)
	if err != nil {
		return b, err
	}
	b.Reporting = fc.Total - fc.Stale - fc.Pending
	b.Score, b.Compliant, b.NonCompliant, b.Stale, b.Pending = percent(fc.Compliant, b.Reporting), fc.Compliant, fc.Noncompl, fc.Stale, fc.Pending
	b.Frameworks = frameworkStats(fc)
	scope, sargs := scopeCond(sess, 0)
	rows, err := s.db.Query(ctx, `SELECT d.id, d.hostname, d.last_seen, d.agent_version, d.catalog_version, d.checks FROM devices d
		WHERE NOT d.retired AND `+scope+` ORDER BY d.hostname, d.id`, sargs...)
	if err != nil {
		return b, err
	}
	defer rows.Close()
	for rows.Next() {
		var d evidenceDevice
		var raw []byte
		if err := rows.Scan(&d.ID, &d.Hostname, &d.LastSeen, &d.AgentVersion, &d.CatalogVersion, &raw); err != nil {
			return b, err
		}
		if err := json.Unmarshal(raw, &d.Checks); err != nil {
			return b, err
		}
		if d.Checks == nil {
			d.Checks = []api.CheckResult{}
		}
		b.CatalogVersions[d.CatalogVersion]++
		b.AgentVersions[d.AgentVersion]++
		b.Devices = append(b.Devices, d)
	}
	if err := rows.Err(); err != nil {
		return b, err
	}
	ex, err := s.riskExceptions(ctx)
	if err != nil {
		return b, err
	}
	b.Exceptions = apiExceptionsOf(ex)
	if sess.Tenant == 0 && !sess.scoped() {
		if b.History, err = s.fleetHistory(ctx, days); err != nil {
			return b, err
		}
	}
	scope, sargs = scopeCond(sess, 1)
	rows, err = s.db.Query(ctx, `SELECT c.device_id, c.check_id, c.status, c.detail, c.at, c.catalog_version FROM compliance_changes c
		JOIN devices d ON d.id = c.device_id WHERE c.at >= now() - make_interval(days => $1) AND `+scope+` ORDER BY c.id LIMIT `+strconv.Itoa(maxEvidenceChanges), append([]any{days}, sargs...)...)
	if err != nil {
		return b, err
	}
	if b.Changes, err = pgx.CollectRows(rows, pgx.RowToStructByPos[evidenceChange]); err != nil {
		return b, err
	}
	return b, nil
}

// signEvidence marshals and signs a bundle with the command key.
func (s *Server) signEvidence(b evidenceBundle) ([]byte, evidenceSignature, error) {
	if s.cmdKey == nil {
		return nil, evidenceSignature{}, errors.New("no command key to sign evidence with")
	}
	payload, err := json.Marshal(b)
	if err != nil {
		return nil, evidenceSignature{}, err
	}
	sig, err := signEd25519(s.cmdKey, evidenceMessage(payload))
	if err != nil {
		return nil, evidenceSignature{}, fmt.Errorf("signing evidence: %w", err)
	}
	pub, ok := s.cmdKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, evidenceSignature{}, errors.New("the command key is no Ed25519 key")
	}
	es := evidenceSignature{Alg: "ed25519", PublicKey: hex.EncodeToString(pub), KeyID: keyID(pub), Value: hex.EncodeToString(sig)}
	out, err := json.MarshalIndent(signedEvidence{Payload: payload, Signature: es}, "", " ")
	return out, es, err
}

// EvidenceInfo describes a verified evidence file.
type EvidenceInfo struct {
	GeneratedAt time.Time
	GeneratedBy string
	KeyID       string
	Devices     int
	Exceptions  int
	Changes     int
}

// VerifyEvidence checks an evidence file against the given command public
// keys (the current one and, after a rotation, earlier ones).
func VerifyEvidence(data []byte, keys []ed25519.PublicKey) (EvidenceInfo, error) {
	var f signedEvidence
	if err := json.Unmarshal(data, &f); err != nil {
		return EvidenceInfo{}, fmt.Errorf("not an evidence file: %w", err)
	}
	if f.Signature.Alg != "ed25519" {
		return EvidenceInfo{}, fmt.Errorf("unknown signature algorithm %q", f.Signature.Alg)
	}
	sig, err := hex.DecodeString(f.Signature.Value)
	if err != nil {
		return EvidenceInfo{}, errors.New("signature: not hex")
	}
	// the payload was signed compact; the file is indented for reading
	var buf bytes.Buffer
	if err := json.Compact(&buf, f.Payload); err != nil {
		return EvidenceInfo{}, fmt.Errorf("payload: %w", err)
	}
	payload := buf.Bytes()
	i := slices.IndexFunc(keys, func(k ed25519.PublicKey) bool { return ed25519.Verify(k, evidenceMessage(payload), sig) })
	if i < 0 {
		return EvidenceInfo{}, errors.New("signature does not verify with the command key")
	}
	var b evidenceBundle
	if err := json.Unmarshal(payload, &b); err != nil || b.Format != evidenceFormat {
		return EvidenceInfo{}, fmt.Errorf("unknown evidence format %q", b.Format)
	}
	return EvidenceInfo{GeneratedAt: b.GeneratedAt, GeneratedBy: b.GeneratedBy, KeyID: keyID(keys[i]), Devices: len(b.Devices),
		Exceptions: len(b.Exceptions), Changes: len(b.Changes)}, nil
}

// CommandPublicKeys are the public command keys of a CA directory: the
// active one first, then the previous one while a rotation runs.
func CommandPublicKeys(caDir string, p KeyProvider) ([]ed25519.PublicKey, error) {
	st, err := readKeyStates(caDir)
	if err != nil {
		return nil, err
	}
	var out []ed25519.PublicKey
	for _, name := range []string{st[kindCommand].Active, st[kindCommand].Previous} {
		if name == "" && len(out) > 0 {
			continue
		}
		k, err := loadCommandKey(p, caDir, name, false)
		if err != nil {
			if len(out) > 0 {
				continue
			}
			return nil, err
		}
		if pub, ok := k.Public().(ed25519.PublicKey); ok {
			out = append(out, pub)
		}
	}
	return out, nil
}

// evidenceDays reads the history window (days, default 90, 1..365).
func evidenceDays(r *http.Request) (int, bool) {
	v := r.URL.Query().Get("days")
	if v == "" {
		return 90, true
	}
	n, err := strconv.Atoi(v)
	return n, err == nil && n >= 1 && n <= 365
}

// evidenceExport streams the signed bundle (evidence.json) or the PDF
// report (evidence.pdf) through streamExport, so both are audited like the
// CSV exports; the bundle's SHA-256 and key are audited as evidence.sign.
func (s *Server) evidenceExport(w http.ResponseWriter, r *http.Request, sess session, kind string) {
	ctx := r.Context()
	days, ok := evidenceDays(r)
	if !ok {
		http.Error(w, "days must be 1..365", http.StatusBadRequest)
		return
	}
	b, err := s.buildEvidence(ctx, sess, days)
	if err != nil {
		s.fail(w, err)
		return
	}
	file, sig, err := s.signEvidence(b)
	if err != nil {
		s.fail(w, err)
		return
	}
	sum := sha256.Sum256(file)
	if err := s.auditAction(ctx, sess.Email, "evidence.sign", kind, fmt.Sprintf("bundle_sha256=%x key_id=%s devices=%d", sum, sig.KeyID, len(b.Devices)), nil); err != nil {
		s.fail(w, err)
		return
	}
	var body []byte
	ctype := "application/json"
	if kind == "evidence.pdf" {
		ctype = "application/pdf"
		body = evidencePDF(requestLang(r), b, hex.EncodeToString(sum[:]), sig)
	} else {
		body = file
	}
	s.streamExport(w, r, sess, kind, ctype, func(_ pgx.Tx, out io.Writer) (int, error) {
		_, err := out.Write(body)
		return len(b.Devices), err
	})
}
