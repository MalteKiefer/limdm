package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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
	Failing  int       `json:"failing_checks,omitempty"`
	Since    time.Time `json:"noncompliant_since,omitzero"`
	Detail   string    `json:"detail,omitempty"` // device.tamper: what was found
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
	if locked && c.LockAfterHours == 0 {
		// the lock action was removed from the policy: lift the automatic lock
		if err := s.queuePolicyCommand(ctx, tx, deviceID, "unlock", false); err != nil {
			return nil, err
		}
		if err := audit(ctx, tx, "policy", "compliance.unlock", deviceID, "lock action no longer declared"); err != nil {
			return nil, err
		}
		locked = false
	}
	if failing == 0 {
		if since == nil && !locked {
			return nil, nil
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET noncompliant_since=NULL, grace_until=NULL, notified_at=NULL WHERE id=$1`, deviceID); err != nil {
			return nil, err
		}
		if locked && c.UnlockWhenCompliant {
			if err := s.queuePolicyCommand(ctx, tx, deviceID, "unlock", false); err != nil {
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
		if err := s.queuePolicyCommand(ctx, tx, deviceID, "lock", true); err != nil {
			return nil, err
		}
		if err := audit(ctx, tx, "policy", "compliance.lock", deviceID, fmt.Sprintf("non-compliant for %d h", c.LockAfterHours)); err != nil {
			return nil, err
		}
	}
	return ev, nil
}

func (s *Server) queuePolicyCommand(ctx context.Context, tx pgx.Tx, deviceID, typ string, locked bool) error {
	if _, err := s.insertCommand(ctx, tx, deviceID, typ, "", "policy"); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE devices SET auto_locked=$2 WHERE id=$1`, deviceID, locked)
	return err
}

// sendWebhook posts the event with an HMAC-SHA256 signature; failures are logged.
func (s *Server) sendWebhook(ev *webhookEvent) {
	target := s.settings().WebhookURL
	if ev == nil || target == "" {
		return
	}
	body, err := json.Marshal(ev)
	if err != nil {
		s.log.Error("webhook", "err", err)
		return
	}
	// the timestamp is signed with the body, so receivers can reject replays
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, s.webhookKey())
	mac.Write([]byte(ts + "."))
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
		req.Header.Set("X-LiMDM-Timestamp", ts)
		req.Header.Set("X-LiMDM-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		client := s.hooks
		if client == nil {
			client = webhookClient
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

// webhookClient does not follow redirects: a redirect could point the server
// at internal addresses (blind SSRF).
// It shares the notification transport: no loopback, link-local or metadata
// targets (the legacy webhook URL is set in the console like a channel).
var webhookClient = notifyClient

// insertCommand stores a command with its signature: the ID and creation
// time come from the insert, the signature covers them with the payload.
// Every path (console, admin API, four eyes approval) queues through here,
// so a wipe revokes the device's network certificates on all of them.
func (s *Server) insertCommand(ctx context.Context, tx pgx.Tx, deviceID, typ, payload, by string) (int64, error) {
	c := api.Command{Type: typ, Payload: payload}
	if typ == "wipe" { // a wiped device no longer needs network access
		if err := revokeNetworkCerts(ctx, tx, deviceID, "wiped"); err != nil {
			return 0, err
		}
	}
	if err := tx.QueryRow(ctx, `INSERT INTO commands(device_id, type, payload, created_by, created_at) VALUES ($1,$2,$3,$4, date_trunc('microseconds', now()))
		RETURNING id, created_at`, deviceID, typ, payload, by).Scan(&c.ID, &c.CreatedAt); err != nil {
		return 0, err
	}
	sig, err := signEd25519(s.cmdKey, api.CommandSigned(deviceID, c))
	if err != nil {
		return 0, fmt.Errorf("signing the command: %w", err)
	}
	_, err = tx.Exec(ctx, `UPDATE commands SET signature=$2 WHERE id=$1`, c.ID, hex.EncodeToString(sig))
	return c.ID, err
}
