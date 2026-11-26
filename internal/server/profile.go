package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"rsc.io/qr"
)

// The profile lets every console user choose the language. Local accounts
// also change their password, replace the TOTP secret (confirmed with a code
// from the new secret before it takes effect) and generate recovery codes.
// Recovery codes are shown once and stored as SHA-256 hashes; each works once
// in place of a TOTP code.

const recoveryCount = 10

// Recovery codes carry 120 bits (24 base32 characters), above the 112 bits
// NIST SP 800-63B 5.1.2.2 requires for lookup secrets stored as plain hashes.
// Codes from v0.6.0 (12 characters) are still accepted until they are replaced.
var recoveryCodeRe = regexp.MustCompile(`^[a-z2-7]{4}(-[a-z2-7]{4}){5}$|^[a-z2-7]{4}(-[a-z2-7]{4}){2}$`)

func newRecoveryCode() string {
	b := make([]byte, 15) // 120 bits, exactly 24 base32 characters
	rand.Read(b)
	s := strings.ToLower(b32.EncodeToString(b))
	parts := make([]string, 0, 6)
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:i+4])
	}
	return strings.Join(parts, "-")
}

func hashCode(c string) string {
	h := sha256.Sum256([]byte("limdm recovery code v1\x00" + strings.ToLower(strings.TrimSpace(c))))
	return hex.EncodeToString(h[:])
}

// useRecoveryCode consumes a code inside the login transaction.
func useRecoveryCode(ctx context.Context, tx pgx.Tx, name, code string) (bool, error) {
	if !recoveryCodeRe.MatchString(strings.ToLower(strings.TrimSpace(code))) {
		return false, nil
	}
	tag, err := tx.Exec(ctx, `UPDATE local_recovery_codes SET used_at=now() WHERE name=$1 AND hash=$2 AND used_at IS NULL`, name, hashCode(code))
	return err == nil && tag.RowsAffected() == 1, err
}

// qrSVG renders text as an inline SVG QR code (the CSP forbids data: images).
func qrSVG(text string) template.HTML {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return ""
	}
	var b strings.Builder
	n := c.Size + 8
	fmt.Fprintf(&b, `<svg class="qr" viewBox="0 0 %d %d" role="img" aria-label="QR code"><rect class="qr-bg" width="%d" height="%d"/><path class="qr-fg" d="`, n, n, n, n)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+4, y+4)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return template.HTML(b.String()) //nolint:gosec // numbers only
}

// checkCurrent verifies the current password, with the same lockout as the login.
func (s *Server) checkCurrent(ctx context.Context, tx pgx.Tx, name, password string) error {
	var hash string
	var failures int
	var lockedUntil *time.Time
	if err := tx.QueryRow(ctx, `SELECT password_hash, failures, locked_until FROM local_admins WHERE name=$1 AND NOT disabled FOR UPDATE`, name).
		Scan(&hash, &failures, &lockedUntil); err != nil {
		return err
	}
	if lockedUntil != nil && time.Now().Before(*lockedUntil) {
		checkPassword(dummyHash, password) // same timing as a real check
		return errLocked
	}
	if checkPassword(hash, password) {
		return nil
	}
	failures++
	var lock *time.Time
	if failures >= maxFailures {
		t := time.Now().Add(lockoutDuration)
		lock, failures = &t, 0
	}
	if _, err := tx.Exec(ctx, `UPDATE local_admins SET failures=$2, locked_until=$3 WHERE name=$1`, name, failures, lock); err != nil {
		return err
	}
	return errWrongPassword
}

var (
	errWrongPassword = &userError{http.StatusUnprocessableEntity, "the current password is wrong"}
	errLocked        = &userError{http.StatusTooManyRequests, "too many attempts, try again later"}
	errOIDCProfile   = &userError{http.StatusUnprocessableEntity, "OIDC accounts are managed by the identity provider."}
)

// profileName is the local account name of sess, or errOIDCProfile.
func profileName(sess session) (string, error) {
	name, ok := strings.CutPrefix(sess.Email, localPrefix)
	if !ok {
		return "", errOIDCProfile
	}
	return name, nil
}

// changePassword sets a new password of the local account of sess after
// checking the current one. The caller renews the session.
func (s *Server) changePassword(ctx context.Context, sess session, ip, current, pw, again string) error {
	name, err := profileName(sess)
	if err != nil {
		return err
	}
	if msg := s.settings().Rules.Check(pw, name); msg != "" {
		return &userError{http.StatusUnprocessableEntity, msg}
	}
	if pw != again {
		return &userError{http.StatusUnprocessableEntity, "The new passwords do not match."}
	}
	err = s.auditAction(ctx, sess.Email, "profile.password", sess.Email, "password changed", func(tx pgx.Tx) error {
		if err := s.checkCurrent(ctx, tx, name, current); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE local_admins SET password_hash=$2, session_gen=session_gen+1 WHERE name=$1`, name, hashPassword(pw))
		return err
	})
	return s.profileErr(ctx, sess, name, ip, current, err)
}

// profileErr records a failed password check outside the rolled back transaction.
func (s *Server) profileErr(ctx context.Context, sess session, name, ip, current string, err error) error {
	if !errors.Is(err, errWrongPassword) {
		return err
	}
	_ = s.auditActionFn(ctx, func(tx pgx.Tx) (string, string, string, string, error) {
		err := s.checkCurrent(ctx, tx, name, current)
		if errors.Is(err, errWrongPassword) {
			err = nil
		}
		return sess.Email, "profile.password_check_failed", sess.Email, ip, err
	})
	return err
}

// startTOTP checks the current password and stores a pending TOTP secret,
// which becomes active once confirmTOTP sees a matching code.
func (s *Server) startTOTP(ctx context.Context, sess session, ip, current string) (string, error) {
	name, err := profileName(sess)
	if err != nil {
		return "", err
	}
	secret := newTOTPSecret()
	err = s.auditAction(ctx, sess.Email, "profile.totp_start", sess.Email, "new TOTP secret pending", func(tx pgx.Tx) error {
		if err := s.checkCurrent(ctx, tx, name, current); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE local_admins SET totp_pending=$2 WHERE name=$1`, name, secret)
		return err
	})
	if err != nil {
		return "", s.profileErr(ctx, sess, name, ip, current, err)
	}
	return secret, nil
}

// confirmTOTP activates the pending secret when code matches it. The
// caller renews the session.
func (s *Server) confirmTOTP(ctx context.Context, sess session, code string) error {
	name, err := profileName(sess)
	if err != nil {
		return err
	}
	return s.auditAction(ctx, sess.Email, "profile.totp", sess.Email, "TOTP secret replaced", func(tx pgx.Tx) error {
		var pending *string
		if err := tx.QueryRow(ctx, `SELECT totp_pending FROM local_admins WHERE name=$1 FOR UPDATE`, name).Scan(&pending); err != nil {
			return err
		}
		if pending == nil {
			return &userError{http.StatusConflict, "no new secret pending"}
		}
		step, ok := verifyTOTP(*pending, code, time.Now(), 0)
		if !ok {
			return &userError{http.StatusUnprocessableEntity, "the code does not match the new secret"}
		}
		_, err := tx.Exec(ctx, `UPDATE local_admins SET totp_secret=totp_pending, totp_pending=NULL, totp_last_step=$2,
			session_gen=session_gen+1 WHERE name=$1`, name, step)
		return err
	})
}

// cancelTOTP drops a pending TOTP secret.
func (s *Server) cancelTOTP(ctx context.Context, sess session) error {
	name, err := profileName(sess)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `UPDATE local_admins SET totp_pending=NULL WHERE name=$1`, name)
	return err
}

// newRecoveryCodes checks the current password and replaces all recovery
// codes of the local account of sess.
func (s *Server) newRecoveryCodes(ctx context.Context, sess session, ip, current string) ([]string, error) {
	name, err := profileName(sess)
	if err != nil {
		return nil, err
	}
	codes := make([]string, recoveryCount)
	for i := range codes {
		codes[i] = newRecoveryCode()
	}
	err = s.auditAction(ctx, sess.Email, "profile.recovery_codes", sess.Email, fmt.Sprintf("%d new recovery codes", recoveryCount), func(tx pgx.Tx) error {
		if err := s.checkCurrent(ctx, tx, name, current); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM local_recovery_codes WHERE name=$1`, name); err != nil {
			return err
		}
		for _, c := range codes {
			if _, err := tx.Exec(ctx, `INSERT INTO local_recovery_codes(name, hash) VALUES ($1,$2)`, name, hashCode(c)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, s.profileErr(ctx, sess, name, ip, current, err)
	}
	return codes, nil
}
