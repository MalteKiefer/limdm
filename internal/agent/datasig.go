package agent

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Catalog apps, managed remotes and the device user list make the agent act
// as root (repositories, packages, sudo membership). A server that signs
// them says so (SignedData); once a command key is pinned, entries without
// a valid signature of that key are refused, so a database write on the
// server alone cannot reach devices. Servers that do not sign yet are
// trusted as before.

// commandKeys are the pinned key and, during a rollover grace, the previous one.
func (a *Agent) commandKeys() []ed25519.PublicKey {
	var keys []ed25519.PublicKey
	if b, err := hex.DecodeString(a.state.CommandKey); err == nil && len(b) == ed25519.PublicKeySize {
		keys = append(keys, b)
	}
	if b, err := hex.DecodeString(a.state.CommandKeyPrev); err == nil && len(b) == ed25519.PublicKeySize && time.Now().Before(a.state.CommandKeyPrevUntil) {
		keys = append(keys, b)
	}
	return keys
}

func signedBy(keys []ed25519.PublicKey, msg []byte, sig string) bool {
	return slices.ContainsFunc(keys, func(k ed25519.PublicKey) bool { return api.VerifySigned(k, msg, sig) })
}

// verifyCatalog drops the apps and remotes whose signature does not verify
// or whose sequence number is below one accepted before.
func (a *Agent) verifyCatalog(signed bool, c *api.Catalog) {
	if !signed || a.state.CommandKey == "" {
		return
	}
	keys := a.commandKeys()
	c.Apps = slices.DeleteFunc(c.Apps, func(app api.CatalogApp) bool {
		err := errors.New("signature invalid")
		if signedBy(keys, api.CatalogAppSigned(app), app.Signature) {
			if err = a.seqOK("app:"+app.ID, app.Seq); err == nil {
				return false
			}
		}
		a.refused("catalog app "+app.ID, err)
		return true
	})
	c.Remotes = slices.DeleteFunc(c.Remotes, func(r api.CatalogRemote) bool {
		err := errors.New("signature invalid")
		if signedBy(keys, api.CatalogRemoteSigned(r), r.Signature) {
			if err = a.seqOK("remote:"+r.Name, r.Seq); err == nil {
				return false
			}
		}
		a.refused("Flatpak remote "+r.Name, err)
		return true
	})
}

// seqOK accepts a signed entry's sequence number unless a higher one of
// the same entry was accepted before (an older signed state written back
// into the server's database), and records it.
func (a *Agent) seqOK(key string, seq int64) error {
	if last := a.state.SignedSeq[key]; seq < last {
		return fmt.Errorf("older than the accepted state (%d < %d)", seq, last)
	}
	if a.state.SignedSeq == nil {
		a.state.SignedSeq = map[string]int64{}
	}
	a.state.SignedSeq[key] = seq
	return nil
}

// verifyUsers returns the device users to apply. The list may be shorter
// than the signed one (people disabled in the directory), never longer and
// never with other rights.
func (a *Agent) verifyUsers(resp api.CheckinResponse) ([]api.User, error) {
	if !resp.SignedData || a.state.CommandKey == "" {
		return resp.Users, nil
	}
	su := resp.SignedUsers
	if su == nil {
		return nil, errors.New("not signed")
	}
	if !signedBy(a.commandKeys(), api.UsersSigned(a.cfg.DeviceID, su.Users, su.Seq), su.Signature) {
		return nil, errors.New("signature invalid")
	}
	for _, u := range resp.Users {
		if !slices.Contains(su.Users, u) {
			return nil, fmt.Errorf("user %s is not in the signed list", u.Username)
		}
	}
	if err := a.seqOK("users", su.Seq); err != nil {
		return nil, err
	}
	return resp.Users, nil
}

// refused records a refusal (event suppresses repeats).
func (a *Agent) refused(what string, err error) {
	a.event("refused the %s from the server: %v", what, err)
}
