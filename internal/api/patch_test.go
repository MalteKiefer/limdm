package api

import (
	"slices"
	"testing"
)

func TestUpdateRules(t *testing.T) {
	ok := `{"window":"02:00-05:00","days":["sat"],"rules":[{"source":"os_security","mode":"install"},{"source":"third_party","mode":"install","rings":true,"repos":["Docker CE","google-chrome*"],"window":"22:00-23:00"},{"source":"flatpak","mode":"notify"}],"security_max_days":7}`
	if err := valid(TypeUpdates, ok); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"no mode, no rules": `{"window":"02:00-05:00"}`,
		"source":            `{"rules":[{"source":"snap","mode":"install"}],"window":"02:00-05:00"}`,
		"twice":             `{"rules":[{"source":"flatpak","mode":"install"},{"source":"flatpak","mode":"off"}],"window":"02:00-05:00"}`,
		"rule mode":         `{"rules":[{"source":"flatpak","mode":"all"}],"window":"02:00-05:00"}`,
		"no window":         `{"rules":[{"source":"flatpak","mode":"install"}]}`,
		"repos on os":       `{"rules":[{"source":"os_all","mode":"install","repos":["x"]}],"window":"02:00-05:00"}`,
		"bad repo":          `{"rules":[{"source":"third_party","mode":"install","repos":["-x"]}],"window":"02:00-05:00"}`,
		"max days":          `{"mode":"security","window":"02:00-05:00","security_max_days":400}`,
	} {
		if valid(TypeUpdates, p) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// an "off" rule needs no window
	if err := valid(TypeUpdates, `{"rules":[{"source":"flatpak","mode":"off"}]}`); err != nil {
		t.Error(err)
	}
}

func TestEffectiveRules(t *testing.T) {
	u := Updates{Mode: "all", Window: "01:00-02:00", Days: []string{"mon"}}
	r := u.EffectiveRules()
	if !slices.Equal(sourcesOf(r), []string{SourceOSAll, SourceThirdParty, SourceFlatpak}) || r[0].Window != "01:00-02:00" || r[2].Days[0] != "mon" || !u.Installs() {
		t.Fatalf("all: %+v", r)
	}
	if r := (Updates{Mode: "security", Window: "01:00-02:00"}).EffectiveRules(); !slices.Equal(sourcesOf(r), []string{SourceOSSecurity}) {
		t.Fatalf("security: %+v", r)
	}
	if len((Updates{Mode: "off"}).EffectiveRules()) != 0 || (Updates{Mode: "off"}).Installs() {
		t.Fatal("off")
	}
	u = Updates{Window: "01:00-02:00", Rules: []UpdateRule{{Source: SourceFlatpak, Mode: "install", Window: "03:00-04:00"}, {Source: SourceOSSecurity, Mode: "notify"}}}
	r = u.EffectiveRules()
	if !slices.Equal(sourcesOf(r), []string{SourceOSSecurity, SourceFlatpak}) || r[0].Window != "01:00-02:00" || r[1].Window != "03:00-04:00" || u.Installs() {
		t.Fatalf("rules: %+v", r)
	}
}
