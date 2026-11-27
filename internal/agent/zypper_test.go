package agent

import (
	"slices"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestSUSEDetection(t *testing.T) {
	for osr, want := range map[string]string{
		"NAME=\"openSUSE Leap\"\nID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\nVERSION_ID=\"15.6\"": "suse",
		"ID=\"opensuse-tumbleweed\"\nID_LIKE=\"opensuse suse\"\nVERSION_ID=\"20261120\"":               "suse",
		"ID=\"sles\"\nID_LIKE=\"suse\"\nVERSION_ID=\"15.7\"":                                           "suse",
		"ID=\"sled\"\nID_LIKE=\"suse\"":                                                                "suse",
	} {
		if got := familyOf(parseOSRelease(osr)); got != want {
			t.Errorf("%q: %q", osr, got)
		}
	}
	if !(&host{ID: "opensuse-tumbleweed"}).rolling() || (&host{ID: "opensuse-leap"}).rolling() {
		t.Fatal("rolling")
	}
	if f := api.PackageName("1.0.0", "amd64", packageFormat("suse")); !strings.HasSuffix(f, ".rpm") {
		t.Fatal(f)
	}
}

func TestZypperCommands(t *testing.T) {
	for _, c := range []struct {
		sec, rolling bool
		want         string
	}{
		{true, false, "patch --category security --auto-agree-with-licenses"},
		{false, false, "update --auto-agree-with-licenses"},
		{true, true, "dup --auto-agree-with-licenses"},
	} {
		if got := strings.Join(zypperUpgradeArgs(c.sec, c.rolling), " "); got != c.want {
			t.Errorf("%v %v: %s", c.sec, c.rolling, got)
		}
	}
	// package names follow "--", never read as options
	if got := zypperInstallArgs([]string{"chrony"}); !slices.Equal(got[len(got)-2:], []string{"--", "chrony"}) {
		t.Fatal(got)
	}
	l, err := parseZypperUpdates(`<?xml version='1.0'?>
<stream>
<message type="info">Loading repository data...</message>
<update-status version="0.6">
<update-list>
<update name="openssl-3" edition="3.1.4-150600.5.21.1" arch="x86_64" kind="package"><summary>x</summary></update>
<update name="vim" edition="9.1.0836-150500.20.21.1" arch="x86_64" kind="package"><source url="https://download.opensuse.org/update/leap/15.6/oss" alias="repo-update"/></update>
<update name="code" edition="1.95" arch="x86_64" kind="package"><source url="https://packages.microsoft.com/yumrepos/vscode" alias="code"/></update>
<update name="openSUSE-SLE-15.6-2024-123" edition="1" arch="noarch" kind="patch" category="security" severity="important"><issue-list><issue type="cve" id="2024-1234"/><issue type="bugzilla" id="1"/></issue-list></update>
</update-list>
</update-status>
</stream>`)
	if err != nil || len(l) != 4 || l[0].Name != "openssl-3" || l[1].Source != api.SourceOSAll || l[2].Source != api.SourceThirdParty ||
		!l[3].Patch || !l[3].Security || l[3].Severity != "important" || len(l[3].CVEs) != 1 || l[3].CVEs[0] != "CVE-2024-1234" {
		t.Fatalf("%+v %v", l, err)
	}
	if l, err := parseZypperUpdates("<stream><update-status/></stream>"); err != nil || len(l) != 0 {
		t.Fatal(l, err)
	}
}

func TestSUSEPackagesAndRepos(t *testing.T) {
	pkgs := missingPackages("suse", true, false, func(string) bool { return false })
	for _, want := range []string{"gpg2", "iproute2", "procps", "libnotify-tools", "typelib-1_0-Gtk-4_0", "audit", "cryptsetup"} {
		if !slices.Contains(pkgs, want) {
			t.Errorf("missing %s in %v", want, pkgs)
		}
	}
	h := &host{family: "suse"}
	r := api.Repository{Name: "vendor", Family: "suse", URL: "https://repo.example.com/rpm/$basearch", Key: "KEY"}
	kn, _, sn, src := h.repoFiles("limdm-", r)
	if kn != "RPM-GPG-KEY-limdm-vendor" || sn != "limdm-vendor.repo" || !strings.Contains(src, "autorefresh=1\ntype=rpm-md") {
		t.Fatalf("%s %s\n%s", kn, sn, src)
	}
	if _, dir := h.repoDirs(); dir != "/etc/zypp/repos.d" || h.repoPath("repo-oss.repo") != "/etc/zypp/repos.d/repo-oss.repo" {
		t.Fatal(dir)
	}
	if mk, cfg := grubConfig("suse"); mk != "grub2-mkconfig" || cfg != "/boot/grub2/grub.cfg" {
		t.Fatal(mk, cfg)
	}
}
