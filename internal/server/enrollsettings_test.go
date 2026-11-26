package server

import "testing"

func TestEnrollTokenLimits(t *testing.T) {
	var e EnrollSettings
	if u, d, err := e.tokenLimits(0, 0); err != nil || u != 1 || d != 1 {
		t.Fatalf("defaults: %d %d %v", u, d, err)
	}
	if _, _, err := e.tokenLimits(501, 1); err == nil {
		t.Fatal("above the hard limit of uses")
	}
	if _, _, err := e.tokenLimits(1, 31); err == nil {
		t.Fatal("above the hard limit of days")
	}
	e = EnrollSettings{MaxUses: 10, MaxDays: 2}
	if _, _, err := e.tokenLimits(11, 1); err == nil {
		t.Fatal("above the configured limit")
	}
	for _, bad := range []EnrollSettings{{MaxUses: 501}, {MaxDays: 31}, {MaxUses: 5, DefaultUses: 6}, {MaxDays: 3, DefaultDays: 4}} {
		if bad.withDefaults().validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if (EnrollSettings{}).withDefaults().validate() != nil {
		t.Fatal("defaults must be valid")
	}
}
