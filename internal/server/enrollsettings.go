package server

import (
	"cmp"
	"fmt"
	"net/http"
)

// Hard limits of an enrollment token. A token is a bearer secret that
// turns any machine into a managed device of the tenant; the settings can
// only lower these.
const (
	tokenHardUses = 500
	tokenHardDays = 30
)

// EnrollSettings are the limits of new enrollment tokens (Settings,
// Enrollment) and whether new devices must hold their key in a TPM.
type EnrollSettings struct {
	DefaultUses int `json:"default_uses"`
	DefaultDays int `json:"default_days"`
	MaxUses     int `json:"max_uses"`
	MaxDays     int `json:"max_days"`
	// RequireTPM refuses enrollments without a TPM bound key in every
	// tenant; tenants can require it on their own (tenants.require_tpm).
	RequireTPM bool `json:"require_tpm"`
}

func (e EnrollSettings) withDefaults() EnrollSettings {
	e.MaxUses = cmp.Or(e.MaxUses, tokenHardUses)
	e.MaxDays = cmp.Or(e.MaxDays, tokenHardDays)
	e.DefaultUses = cmp.Or(e.DefaultUses, 1)
	e.DefaultDays = cmp.Or(e.DefaultDays, 1)
	return e
}

func (e EnrollSettings) validate() error {
	if e.MaxUses < 1 || e.MaxUses > tokenHardUses || e.MaxDays < 1 || e.MaxDays > tokenHardDays {
		return fmt.Errorf("enrollment token limits: 1 to %d uses and 1 to %d days", tokenHardUses, tokenHardDays)
	}
	if e.DefaultUses < 1 || e.DefaultUses > e.MaxUses || e.DefaultDays < 1 || e.DefaultDays > e.MaxDays {
		return fmt.Errorf("enrollment token defaults must be within the limits")
	}
	return nil
}

// tokenLimits resolves the uses and days of a new token: 0 takes the
// default, anything above the maximum is refused.
func (e EnrollSettings) tokenLimits(uses, days int) (int, int, error) {
	e = e.withDefaults()
	uses, days = cmp.Or(uses, e.DefaultUses), cmp.Or(days, e.DefaultDays)
	if uses < 1 || uses > e.MaxUses || days < 1 || days > e.MaxDays {
		return 0, 0, &userError{http.StatusBadRequest, fmt.Sprintf("uses 1 to %d, days 1 to %d", e.MaxUses, e.MaxDays)}
	}
	return uses, days, nil
}
