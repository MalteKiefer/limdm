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
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	if checkIdentity("https://idp.example", "A@Firma.de", true, "firma.de", "a@firma.de", "firma.de") != nil {
		t.Fatal("valid identity rejected")
	}
	for _, c := range [][]string{
		{"b@firma.de", "firma.de"},  // other user
		{"a@firma.de.evil", "evil"}, // wrong domain
	} {
		if checkIdentity("https://idp.example", c[0], true, c[1], "a@firma.de", "firma.de") == nil {
			t.Errorf("%v accepted", c)
		}
	}
	if checkIdentity("https://idp.example", "a@firma.de", false, "firma.de", "a@firma.de", "firma.de") == nil {
		t.Fatal("unverified email accepted")
	}
	// Google: a consumer account with a verified company address has no hd claim
	if checkIdentity("https://accounts.google.com", "a@firma.de", true, "", "a@firma.de", "firma.de") == nil {
		t.Fatal("Google account without hd accepted")
	}
	if checkIdentity("https://accounts.google.com", "a@firma.de", true, "firma.de", "a@firma.de", "firma.de") != nil {
		t.Fatal("Workspace account rejected")
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
	local := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\nadmin:x:5001:5001::/home/admin:/usr/bin/fish\nanna:x:1001:1001:Anna A,,,:/home/anna:/bin/bash\n"
	nss := local + "jdoe:*:70001:70001:John Doe:/home/jdoe:/bin/bash\nsystemd-dyn:x:61234:61234::/:/usr/sbin/nologin\n"
	localGroup := "sudo:x:27:admin\nwheel:x:10:\nusers:x:100:anna\n"
	nssGroup := localGroup + "engineers:*:70100:jdoe,anna\n"
	users, groups := parseAccounts(nss, nssGroup, local, localGroup)
	byName := map[string]api.Account{}
	for _, u := range users {
		byName[u.Name] = u
	}
	if len(users) != 6 || !byName["root"].Admin || !byName["admin"].Admin || byName["anna"].Admin || byName["anna"].Gecos != "Anna A" {
		t.Fatalf("users: %+v", users)
	}
	if byName["jdoe"].Source != "nss" || byName["anna"].Source != "local" || !byName["daemon"].System || !byName["systemd-dyn"].System || byName["jdoe"].System {
		t.Fatalf("sources: %+v", users)
	}
	if len(groups) != 4 || groups[3].Name != "engineers" || groups[3].Source != "nss" || len(groups[3].Members) != 2 {
		t.Fatalf("groups: %+v", groups)
	}
}

func TestRepoParsers(t *testing.T) {
	list := "# comment\ndeb [arch=amd64 signed-by=/k.asc] https://a.example/deb stable main\ndeb http://b.example/ bookworm main contrib\ndeb-src http://c/ x y\n"
	r := parseAptList(list, "/etc/apt/sources.list")
	if len(r) != 2 || !r[0].Signed || r[1].Signed || r[1].Suites != "bookworm" || r[1].Components != "main contrib" {
		t.Fatalf("list: %+v", r)
	}
	d822 := "Types: deb deb-src\nURIs: https://deb.debian.org/debian\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: https://x/\nSuites: s\nEnabled: no\n"
	r = parseDeb822(d822, "/etc/apt/sources.list.d/debian.sources")
	if len(r) != 2 || !r[0].Signed || r[0].Suites != "trixie trixie-updates" || r[0].Components != "main" || r[1].Enabled {
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

func TestPolkitAndSudoRendering(t *testing.T) {
	js := polkitJS(api.PolkitRule{Name: "net", Actions: []string{"org.freedesktop.NetworkManager.*", "org.freedesktop.timedate1.set-timezone"},
		Groups: []string{"netdev"}, Result: "auth_self_keep", LocalActiveOnly: true})
	for _, want := range []string{`action.id.indexOf("org.freedesktop.NetworkManager.") == 0`, `action.id == "org.freedesktop.timedate1.set-timezone"`,
		`subject.isInGroup("netdev")`, "subject.local && subject.active", "polkit.Result.AUTH_SELF_KEEP"} {
		if !strings.Contains(js, want) {
			t.Errorf("polkit rule lacks %q:\n%s", want, js)
		}
	}
	line := sudoLine(api.SudoRule{Principals: []string{"%dev", "alice"}, Commands: []string{"/usr/bin/apt-get update", "/usr/bin/systemctl restart nginx"}, NoPasswd: true})
	if line != "%dev, alice ALL=(root) NOPASSWD: /usr/bin/apt-get update, /usr/bin/systemctl restart nginx\n" {
		t.Fatalf("sudo line: %q", line)
	}
}

func TestDesktopServer(t *testing.T) {
	a := &Agent{kick: make(chan struct{}, 1)}
	d := &desktopServer{a: a, queued: map[string]bool{"u2": true}, inflight: map[string]bool{}, failures: map[uint32][]time.Time{}}
	d.info.Store(&desktopInfo{Company: "ACME", Need: []luksVolume{{"/dev/sda3", "u1"}, {"/dev/sdb1", "u2"}}})
	st := d.serve(1000, DesktopRequest{Op: "status"})
	if st.Company != "ACME" || len(st.Need) != 1 || st.Need[0].UUID != "u1" {
		t.Fatalf("status: %+v", st)
	}
	if r := d.serve(1000, DesktopRequest{Op: "escrow", UUID: "u2", Passphrase: "x"}); r.OK || r.Error == "" {
		t.Fatal("queued volume accepted again")
	}
	if r := d.serve(1000, DesktopRequest{Op: "escrow", UUID: "u1"}); r.OK {
		t.Fatal("empty passphrase accepted")
	}
	for range 5 {
		d.recordFailure(1000)
	}
	if r := d.serve(1000, DesktopRequest{Op: "escrow", UUID: "u1", Passphrase: "x"}); !strings.Contains(r.Error, "too many") {
		t.Fatalf("rate limit: %+v", r)
	}
	if !d.allowAttempt(1001) {
		t.Fatal("rate limit must be per user")
	}
}

func TestDisableRepoContent(t *testing.T) {
	list := disableRepoContent("x.list", "# comment\ndeb https://a/ stable main\n")
	if r := parseAptList(list, "x.list"); len(r) != 1 || r[0].Enabled {
		t.Fatalf("list: %q %+v", list, r)
	}
	src := disableRepoContent("d.sources", "Types: deb\nURIs: https://a/\nSuites: s\nEnabled: yes\n\nTypes: deb\nURIs: https://b/\nSuites: t\n")
	if r := parseDeb822(src, "d.sources"); len(r) != 2 || r[0].Enabled || r[1].Enabled {
		t.Fatalf("deb822: %q %+v", src, r)
	}
	repo := disableRepoContent("f.repo", "[a]\nname=a\nbaseurl=https://a/\nenabled=1\n[b]\nbaseurl=https://b/\n")
	if r := parseYumRepo(repo, "f.repo"); len(r) != 2 || r[0].Enabled || r[1].Enabled {
		t.Fatalf("repo: %q %+v", repo, r)
	}
}

func TestEnrollConfigErrors(t *testing.T) {
	f := filepath.Join(t.TempDir(), "enroll.conf")
	os.WriteFile(f, []byte("# c\nserver = \"https://mdm.example.com:8444\"\nfingerprint = 'ab'\n"), 0o600)
	if err := EnrollFromConfig(f); err == nil || !strings.Contains(err.Error(), "token is missing") {
		t.Fatalf("want missing token, got %v", err)
	}
	os.WriteFile(f, []byte("garbage\n"), 0o600)
	if err := EnrollFromConfig(f); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestLocalPasswordRules(t *testing.T) {
	p := pamPolicy{Login: api.Login{Enabled: true, LocalPassword: true, ReverifyHours: 24}}
	if !ssoDue(p, "nobody-ever-confirmed", time.Now()) {
		t.Fatal("unconfirmed user must need SSO")
	}
	if !ssoDue(pamPolicy{Login: api.Login{Enabled: true}}, "x", time.Now()) {
		t.Fatal("pure SSO mode must always need SSO")
	}
	for pw, ok := range map[string]bool{"short": false, "correct horse battery": true, "anna-is-my-name-ok": false, "line\nbreak-password": false} {
		if (checkLocalPassword("anna", pw) == nil) != ok {
			t.Errorf("password %q: want ok=%v", pw, ok)
		}
	}
	old := "auth\trequired\tpam_env.so\nauth [success=end default=ignore] pam_exec.so quiet stdout /usr/bin/limdm-agent pam-auth\nauth\tsufficient\tpam_unix.so\n"
	got, err := insertPAMLine(old, "auth sufficient "+pamLine("/usr/bin/limdm-agent"))
	if err != nil || strings.Count(got, "pam-auth") != 1 || !strings.Contains(got, "expose_authtok") {
		t.Fatalf("PAM line not replaced: %v\n%s", err, got)
	}
}

func TestCommandsRunOnce(t *testing.T) {
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.state.DoneCommands = map[int64]time.Time{7: time.Now()}
	a.runCommands([]api.Command{{ID: 7, Type: "sync"}})
	if len(a.state.Results) != 1 || a.state.Results[0].ID != 7 {
		t.Fatalf("redelivered command must be answered, not rerun: %+v", a.state.Results)
	}
	a.runCommands([]api.Command{{ID: 7, Type: "sync"}})
	if len(a.state.Results) != 1 {
		t.Fatalf("pending result duplicated: %+v", a.state.Results)
	}
}

func TestPAMServiceFilter(t *testing.T) {
	for _, c := range []struct {
		service, rhost string
		want           bool
	}{{"gdm-password", "", true}, {"login", "", true}, {"sudo", "", true}, {"sshd", "", false},
		{"login", "203.0.113.7", false}, {"sshd", "203.0.113.7", false}, {"cron", "", false}, {"", "", false}} {
		if localService(c.service, c.rhost) != c.want {
			t.Errorf("%s from %q: want %v", c.service, c.rhost, c.want)
		}
	}
}

func TestDesktopRateLimitParallel(t *testing.T) {
	var calls atomic.Int32
	addKeyFn = func(string, string, string) error {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return errors.New("wrong")
	}
	defer func() { addKeyFn = luksAddKey }()
	a := &Agent{kick: make(chan struct{}, 1)}
	d := &desktopServer{a: a, queued: map[string]bool{}, inflight: map[string]bool{}, failures: map[uint32][]time.Time{}}
	vols := make([]luksVolume, 10)
	for i := range vols {
		vols[i] = luksVolume{"/dev/x" + strconv.Itoa(i), "u" + strconv.Itoa(i)}
	}
	d.info.Store(&desktopInfo{Need: vols})
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.serve(1000, DesktopRequest{Op: "escrow", UUID: "u" + strconv.Itoa(i), Passphrase: "x"})
		}()
	}
	wg.Wait()
	if n := calls.Load(); n > 5 {
		t.Fatalf("%d passphrase attempts ran in parallel, limit is 5", n)
	}
}
