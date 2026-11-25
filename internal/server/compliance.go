package server

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Compliance policies (the compliance library type) carry a grace period and
// actions. The server tracks since when a device fails, reports through a
// signed webhook once the grace period is over, and can lock and later unlock
// the device automatically. Every action is audited.

type webhookEvent struct {
	Type     string    `json:"type"` // device.noncompliant
	DeviceID string    `json:"device_id"`
	Hostname string    `json:"hostname"`
	Failing  int       `json:"failing_checks"`
	Since    time.Time `json:"noncompliant_since"`
	Console  string    `json:"console_url"`
}

// enforceCompliance updates the grace state of a device and queues policy
// actions in tx. The returned event, if any, is sent after commit.
func (s *Server) enforceCompliance(ctx context.Context, tx pgx.Tx, deviceID string, c api.Compliance, now time.Time) (*webhookEvent, error) {
	var failing int
	var since, notified *time.Time
	var locked bool
	var host string
	err := tx.QueryRow(ctx, `SELECT failing, noncompliant_since, notified_at, auto_locked, hostname FROM devices WHERE id=$1`, deviceID).
		Scan(&failing, &since, &notified, &locked, &host)
	if err != nil {
		return nil, err
	}
	if failing == 0 {
		if since == nil && !locked {
			return nil, nil
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET noncompliant_since=NULL, grace_until=NULL, notified_at=NULL WHERE id=$1`, deviceID); err != nil {
			return nil, err
		}
		if locked && c.UnlockWhenCompliant {
			if err := queuePolicyCommand(ctx, tx, deviceID, "unlock", false); err != nil {
				return nil, err
			}
			if err := audit(ctx, tx, "policy", "compliance.unlock", deviceID, "compliant again"); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	if since == nil {
		t := now
		since = &t
		if _, err := tx.Exec(ctx, `UPDATE devices SET noncompliant_since=$2, grace_until=$3 WHERE id=$1`,
			deviceID, now, now.Add(time.Duration(c.GraceHours)*time.Hour)); err != nil {
			return nil, err
		}
	}
	var ev *webhookEvent
	if c.Notify && notified == nil && !now.Before(since.Add(time.Duration(c.GraceHours)*time.Hour)) {
		if _, err := tx.Exec(ctx, `UPDATE devices SET notified_at=$2 WHERE id=$1`, deviceID, now); err != nil {
			return nil, err
		}
		if err := audit(ctx, tx, "policy", "compliance.notify", deviceID, fmt.Sprintf("%d failing checks since %s", failing, since.Format(time.RFC3339))); err != nil {
			return nil, err
		}
		ev = &webhookEvent{Type: "device.noncompliant", DeviceID: deviceID, Hostname: host, Failing: failing, Since: *since,
			Console: s.cfg.PublicURL + "/devices/" + deviceID}
	}
	if c.LockAfterHours > 0 && !locked && !now.Before(since.Add(time.Duration(c.LockAfterHours)*time.Hour)) {
		if err := queuePolicyCommand(ctx, tx, deviceID, "lock", true); err != nil {
			return nil, err
		}
		if err := audit(ctx, tx, "policy", "compliance.lock", deviceID, fmt.Sprintf("non-compliant for %d h", c.LockAfterHours)); err != nil {
			return nil, err
		}
	}
	return ev, nil
}

func queuePolicyCommand(ctx context.Context, tx pgx.Tx, deviceID, typ string, locked bool) error {
	if _, err := tx.Exec(ctx, `INSERT INTO commands(device_id, type, created_by) VALUES ($1,$2,'policy')`, deviceID, typ); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE devices SET auto_locked=$2 WHERE id=$1`, deviceID, locked)
	return err
}

// webhookKey derives the HMAC key receivers use to verify X-LiMDM-Signature.
func (s *Server) webhookKey() []byte {
	k, err := hkdf.Key(sha256.New, s.cfg.SessionKey, nil, "limdm webhook signature v1", 32)
	if err != nil {
		panic(err) // fixed parameters, cannot fail
	}
	return k
}

func (s *Server) webhookSecretHex() string { return hex.EncodeToString(s.webhookKey()) }

// sendWebhook posts the event with an HMAC-SHA256 signature; failures are logged.
func (s *Server) sendWebhook(ev *webhookEvent) {
	target := s.settings().WebhookURL
	if ev == nil || target == "" {
		return
	}
	body, _ := json.Marshal(ev)
	mac := hmac.New(sha256.New, s.webhookKey())
	mac.Write(body)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			s.log.Error("webhook", "err", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-LiMDM-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		client := s.hooks
		if client == nil {
			client = http.DefaultClient
		}
		resp, err := client.Do(req)
		if err != nil {
			s.log.Error("webhook", "err", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			s.log.Error("webhook", "status", resp.Status)
		}
	}()
}
