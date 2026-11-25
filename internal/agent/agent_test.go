package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

const fedoraSystemAuth = `auth        required                                     pam_env.so
auth        required                                     pam_faildelay.so delay=2000000
auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
auth        sufficient                                   pam_unix.so nullok
auth        required                                     pam_deny.so

account     required                                     pam_unix.so`

func TestInsertPAMLine(t *testing.T) {
	line := "auth        sufficient                                   " + pamLine("/usr/bin/limdm-agent")
	out, err := insertPAMLine(fedoraSystemAuth, line)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out, "\n")
	if lines[2] != line || !strings.Contains(lines[3], "pam_usertype") {
		t.Fatalf("line must go after env/faildelay, before first real module:\n%s", out)
	}
	again, _ := insertPAMLine(out, line)
	if again != out {
		t.Fatal("insert must be idempotent")
	}
	if _, err := insertPAMLine("account required pam_unix.so", line); err == nil {
		t.Fatal("missing auth section must fail")
	}
}

func TestInWindow(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 1, 1, h, m, 0, 0, time.Local) }
	for _, c := range []struct {
		t    time.Time
		w    string
		want bool
	}{
		{at(3, 0), "02:00-05:00", true}, {at(5, 0), "02:00-05:00", false}, {at(1, 59), "02:00-05:00", false},
		{at(23, 30), "22:00-04:00", true}, {at(3, 0), "22:00-04:00", true}, {at(12, 0), "22:00-04:00", false},
		{at(3, 0), "garbage", false},
	} {
		if got := inWindow(c.t, c.w); got != c.want {
			t.Errorf("%s in %s = %v", c.t.Format("15:04"), c.w, got)
		}
	}
}

func TestAptPending(t *testing.T) {
	out := "Inst libssl3 [3.0.1] (3.0.2 Debian-Security:12/stable-security [amd64])\nInst vim [9.0] (9.1 Debian:12.6/stable [amd64])\nConf vim\n"
	if all, sec := countAptPending(out); all != 2 || sec != 1 {
		t.Fatalf("all=%d sec=%d", all, sec)
	}
}

func TestSSHValue(t *testing.T) {
	if !sshValueOK("4", "<=4") || sshValueOK("6", "<=4") || sshValueOK("0", "<=300") || !sshValueOK("no", "no") {
		t.Fatal("ssh value comparison wrong")
	}
}

func TestCheckIdentity(t *testing.T) {
	if checkIdentity("A@Firma.de", true, "firma.de", "a@firma.de", "firma.de") != nil {
		t.Fatal("valid identity rejected")
	}
	for _, c := range [][]string{
		{"b@firma.de", "firma.de"},  // other user
		{"a@firma.de.evil", "evil"}, // wrong domain
	} {
		if checkIdentity(c[0], true, c[1], "a@firma.de", "firma.de") == nil {
			t.Errorf("%v accepted", c)
		}
	}
	if checkIdentity("a@firma.de", false, "firma.de", "a@firma.de", "firma.de") == nil {
		t.Fatal("unverified email accepted")
	}
}

func TestExcludedCheckNotEnforced(t *testing.T) {
	a := &Agent{pol: api.Policy{Compliance: api.Compliance{Level: 1, Exclude: []string{"net.forwarding"}}}}
	kv := a.groupKV("sysctl")
	if _, ok := kv["net.ipv4.ip_forward"]; ok {
		t.Fatal("excluded check must not end up in the sysctl drop-in")
	}
	if kv["kernel.randomize_va_space"] != "2" {
		t.Fatal("level 1 sysctl missing")
	}
	if _, ok := kv["kernel.dmesg_restrict"]; ok {
		t.Fatal("level 2 sysctl applied at level 1")
	}
}

func TestCatalogUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range catalog {
		if seen[c.ID] || (c.Run == nil && c.Group == "") || len(c.Refs.ISO) == 0 || len(c.Refs.BSI) == 0 {
			t.Errorf("catalog entry %s invalid", c.ID)
		}
		seen[c.ID] = true
	}
}

func TestFetchPinnedCARejectsWrongFingerprint(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(caPEM) }))
	defer srv.Close()
	if _, err := fetchPinnedCA(srv.URL, strings.Repeat("00", 32)); err == nil {
		t.Fatal("wrong fingerprint accepted")
	}
}

func TestSudoDefaultsParsing(t *testing.T) {
	ok := "Defaults use_pty\nDefaults logfile=\"/var/log/sudo.log\"\n"
	if !sudoUsePTY.MatchString(ok) || sudoNoPTY.MatchString(ok) || !sudoLogfile.MatchString(ok) {
		t.Fatal("valid sudoers not recognised")
	}
	for _, bad := range []string{"Defaults !use_pty\n", "# Defaults use_pty\n", "Defaults env_reset\n# logfile=x\n"} {
		if sudoUsePTY.MatchString(bad) && !sudoNoPTY.MatchString(bad) {
			t.Errorf("%q counted as use_pty", bad)
		}
	}
	if sudoLogfile.MatchString("# Defaults logfile=/x\n") {
		t.Fatal("commented logfile counted")
	}
}

func TestUndeclaredUpdatesFail(t *testing.T) {
	a := &Agent{}
	for _, c := range catalog {
		if c.ID == "updates.auto" {
			if st, _ := c.Run(a); st != fail {
				t.Fatal("missing updates declaration must fail")
			}
		}
	}
}

// TestFetchPinnedCA serves a chain [leaf, CA] like the real agent listener.
func TestFetchPinnedCA(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(caPEM) }))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}}
	srv.StartTLS()
	defer srv.Close()
	sum := sha256.Sum256(caDER)
	got, err := fetchPinnedCA(srv.URL, hex.EncodeToString(sum[:]))
	if err != nil || string(got) != string(caPEM) {
		t.Fatalf("pinned CA rejected: %v", err)
	}
	if _, err := fetchPinnedCA(srv.URL, strings.Repeat("ab", 32)); err == nil {
		t.Fatal("wrong fingerprint accepted")
	}
}

func TestNftDropsInput(t *testing.T) {
	accept := "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\tiifname \"wt0\" accept\n\t}\n}"
	drop := "table inet limdm_fw {\n\tchain input {\n\t\ttype filter hook input priority filter - 10; policy drop;\n\t}\n}"
	if nftDropsInput(accept) {
		t.Fatal("accept policy counted as firewall")
	}
	if !nftDropsInput(accept + "\n" + drop) {
		t.Fatal("drop policy chain not recognised")
	}
}

// TestOsqueryKeyFingerprint guards the embedded repository key against swaps.
func TestOsqueryKeyFingerprint(t *testing.T) {
	if !strings.HasPrefix(osqueryKey, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		t.Fatal("embedded osquery key is not an armored public key")
	}
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	cmd := exec.Command("gpg", "--show-keys", "--with-colons")
	cmd.Stdin = strings.NewReader(osqueryKey)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+t.TempDir())
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "fpr:::::::::"+OsqueryKeyFingerprint+":") {
		t.Fatalf("embedded key fingerprint changed:\n%s", out)
	}
}

func TestDesktopVersionParsing(t *testing.T) {
	if got := firstNonEmpty("", "  ", " x "); got != "x" {
		t.Fatalf("firstNonEmpty: %q", got)
	}
}

func TestAccounts(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\nadmin:x:5001:5001::/home/admin:/usr/bin/fish\nanna:x:1001:1001::/home/anna:/bin/bash\nsvc:x:1002:1002::/:/usr/sbin/nologin\n"
	group := "sudo:x:27:admin\nwheel:x:10:\nusers:x:100:anna\n"
	got := accounts(passwd, group)
	if len(got) != 3 || got[0].Name != "root" || !got[0].Admin || !got[1].Admin || got[2].Name != "anna" || got[2].Admin {
		t.Fatalf("accounts: %+v", got)
	}
}

func TestRepoParsers(t *testing.T) {
	list := "# comment\ndeb [arch=amd64 signed-by=/k.asc] https://a.example/deb stable main\ndeb http://b.example/ bookworm main contrib\ndeb-src http://c/ x y\n"
	r := parseAptList(list, "/etc/apt/sources.list")
	if len(r) != 2 || !r[0].Signed || r[1].Signed || r[1].Suites != "bookworm main contrib" {
		t.Fatalf("list: %+v", r)
	}
	d822 := "Types: deb deb-src\nURIs: https://deb.debian.org/debian\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: https://x/\nSuites: s\nEnabled: no\n"
	r = parseDeb822(d822, "/etc/apt/sources.list.d/debian.sources")
	if len(r) != 2 || !r[0].Signed || r[0].Suites != "trixie trixie-updates main" || r[1].Enabled {
		t.Fatalf("deb822: %+v", r)
	}
	yum := "[fedora]\nname=Fedora\nmetalink=https://mirrors/x\nenabled=1\ngpgcheck=1\n[beta]\nbaseurl=https://b/\nenabled=0\ngpgcheck=0\n"
	r = parseYumRepo(yum, "/etc/yum.repos.d/fedora.repo")
	if len(r) != 2 || !r[0].Signed || !r[0].Enabled || r[1].Enabled || r[1].Signed || r[1].URL != "https://b/" {
		t.Fatalf("yum: %+v", r)
	}
}

func TestSyncManaged(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/limdm-old.sources", []byte("x"), 0o644)
	os.WriteFile(dir+"/limdm-osquery.sources", []byte("keep"), 0o644)
	os.WriteFile(dir+"/debian.sources", []byte("foreign"), 0o644)
	changed, err := syncManaged(dir, "limdm-", ".sources", map[string]string{"limdm-new.sources": "y"}, "limdm-osquery.sources")
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	for f, want := range map[string]bool{"limdm-old.sources": false, "limdm-new.sources": true, "limdm-osquery.sources": true, "debian.sources": true} {
		if exists(dir+"/"+f) != want {
			t.Errorf("%s exists=%v", f, !want)
		}
	}
	if changed, _ := syncManaged(dir, "limdm-", ".sources", map[string]string{"limdm-new.sources": "y"}, "limdm-osquery.sources"); changed {
		t.Fatal("second run must not change anything")
	}
}
