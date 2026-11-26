package agent

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	created := time.Now().Add(-time.Minute)
	a.state.DoneCommands = map[int64]time.Time{7: time.Now()}
	a.runCommands([]api.Command{{ID: 7, Type: "sync", CreatedAt: created}})
	if len(a.state.Results) != 1 || a.state.Results[0].ID != 7 || !strings.Contains(a.state.Results[0].Output, "restarted") {
		t.Fatalf("redelivered command must be answered, not rerun: %+v", a.state.Results)
	}
	a.runCommands([]api.Command{{ID: 7, Type: "sync", CreatedAt: created}})
	if len(a.state.Results) != 1 {
		t.Fatalf("pending result duplicated: %+v", a.state.Results)
	}
	// the same ID created later (database restored from a backup) is a new command
	a.state.Results = nil
	a.runCommands([]api.Command{{ID: 7, Type: "sync", CreatedAt: time.Now().Add(time.Minute)}})
	if len(a.state.Results) != 1 || strings.Contains(a.state.Results[0].Output, "restarted") {
		t.Fatalf("a new command with a reused ID must run: %+v", a.state.Results)
	}
}

func TestPAMServiceFilter(t *testing.T) {
	sessionsDir = t.TempDir()
	defer func() { sessionsDir = "/run/systemd/sessions" }()
	os.WriteFile(sessionsDir+"/2", []byte("UID=1000\nTYPE=wayland\nSEAT=seat0\nREMOTE=0\nSERVICE=gdm-password\n"), 0o644)
	os.WriteFile(sessionsDir+"/7", []byte("UID=1001\nTYPE=tty\nREMOTE=1\nREMOTE_HOST=203.0.113.7\nSERVICE=sshd\n"), 0o644)
	os.WriteFile(sessionsDir+"/8", []byte("UID=1001\nTYPE=tty\nREMOTE=0\nSERVICE=systemd-user\n"), 0o644)
	const (
		local  = "0::/user.slice/user-1000.slice/session-2.scope\n"
		ssh    = "0::/user.slice/user-1001.slice/session-7.scope\n"
		noSeat = "0::/user.slice/user-1001.slice/session-8.scope\n"
		getty  = "0::/system.slice/system-getty.slice/getty@tty1.service\n"
		usrMgr = "0::/user.slice/user-1001.slice/user@1001.service/app.slice/x.service\n"
		sshd   = "0::/system.slice/ssh.service\n"
	)
	for _, c := range []struct {
		service, rhost, tty, cgroup string
		want                        bool
	}{
		{"gdm-password", "", ":0", "0::/system.slice/gdm.service\n", true},
		{"login", "", "/dev/tty1", getty, true},
		{"swaylock", "", "", local, true},
		{"polkit-1", "", "", local, true},
		// su and sudo never start a flow, wherever they run (F5)
		{"su", "", "/dev/pts/3", local, false}, {"su-l", "", "", local, false}, {"sudo", "", "", local, false}, {"sudo-i", "", "", local, false},
		{"sshd", "", "", local, false}, {"cron", "", "", local, false}, {"", "", "", local, false},
		// any remote host, pseudo terminal or remote parent session refuses
		{"login", "203.0.113.7", "", getty, false}, {"login", "localhost", "", getty, false},
		{"login", "", "/dev/pts/0", getty, false},
		{"polkit-1", "", "", ssh, false}, {"swaylock", "", "", ssh, false}, {"i3lock", "", "", sshd, false},
		// polkit can authenticate as another user: only in a local seat session
		{"polkit-1", "", "", usrMgr, false}, {"polkit-1", "", "", noSeat, false},
		{"swaylock", "", "", usrMgr, true},
	} {
		if localService(c.service, c.rhost, c.tty, c.cgroup) != c.want {
			t.Errorf("%s from %q tty %q cgroup %q: want %v", c.service, c.rhost, c.tty, c.cgroup, c.want)
		}
	}
	if !remoteCgroup(ssh) || !remoteCgroup(sshd) || remoteCgroup(local) || remoteCgroup(usrMgr) {
		t.Error("remoteCgroup")
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

func TestParseSlots(t *testing.T) {
	luks2 := "LUKS header information\nVersion:       \t2\n\nKeyslots:\n  0: luks2\n\tKey:        512 bits\n  3: luks2\n\tKey:        512 bits\nTokens:\n  0: systemd-tpm2\n"
	if got, err := parseSlots(luks2); err != nil || !slices.Equal(got, []int{0, 3}) {
		t.Fatalf("luks2: %v %v", got, err)
	}
	luks1 := "Version:       \t1\nKey Slot 0: ENABLED\nKey Slot 1: DISABLED\nKey Slot 2: ENABLED\n"
	if got, err := parseSlots(luks1); err != nil || !slices.Equal(got, []int{0, 2}) {
		t.Fatalf("luks1: %v %v", got, err)
	}
	if _, err := parseSlots("garbage"); err == nil {
		t.Fatal("unparsable dump accepted")
	}
	if m := unlocked.FindStringSubmatch("Key slot 3 unlocked.\nCommand successful."); m == nil || m[1] != "3" {
		t.Fatal("unlocked slot not parsed")
	}
}

func TestParseFlatpak(t *testing.T) {
	apps := parseFlatpakApps("org.mozilla.firefox\tFirefox\t133.0\tstable\tflathub\norg.gnome.Calculator\tCalculator\t\tstable\tfedora\n", "malte")
	if len(apps) != 2 || apps[0].Name != "Firefox" || apps[1].Origin != "fedora" || apps[1].Installation != "malte" {
		t.Fatalf("apps: %+v", apps)
	}
	rem := parseFlatpakRemotes("flathub\thttps://dl.flathub.org/repo/\tFlathub\tsystem\nfedora\toci+https://registry.fedoraproject.org\tFedora\tsystem,oci,disabled\n", "system")
	if len(rem) != 2 || rem[0].Disabled || !rem[1].Disabled || rem[0].Title != "Flathub" {
		t.Fatalf("remotes: %+v", rem)
	}
}

func TestDesktopInfoAndSync(t *testing.T) {
	a := &Agent{kick: make(chan struct{}, 1)}
	d := &desktopServer{a: a, queued: map[string]bool{}, inflight: map[string]bool{}, failures: map[uint32][]time.Time{}}
	d.info.Store(&desktopInfo{Company: "ACME", Status: DesktopStatus{Version: "1.0", Failing: []string{"Firewall"}}})
	info := d.serve(1000, DesktopRequest{Op: "info"})
	if info.Status == nil || info.Status.Version != "1.0" || len(info.Status.Failing) != 1 {
		t.Fatalf("info: %+v", info)
	}
	if r := d.serve(1000, DesktopRequest{Op: "sync"}); !r.OK || len(a.kick) != 1 {
		t.Fatalf("sync: %+v", r)
	}
	if r := d.serve(1000, DesktopRequest{Op: "sync"}); r.OK || r.Error == "" {
		t.Fatal("a second sync within 30 seconds must be refused")
	}
}

func TestMissingPackages(t *testing.T) {
	none := func(string) bool { return false }
	all := func(string) bool { return true }
	if p := missingPackages("debian", false, false, all); len(p) != 0 {
		t.Fatalf("nothing missing: %v", p)
	}
	srv := missingPackages("debian", false, false, none)
	if slices.Contains(srv, "zenity") || slices.Contains(srv, "libnotify-bin") || !slices.Contains(srv, "cryptsetup-bin") {
		t.Fatalf("server: %v", srv)
	}
	if n := len(srv); n != len(slices.Compact(slices.Sorted(slices.Values(srv)))) {
		t.Fatalf("duplicates: %v", srv)
	}
	kde := missingPackages("fedora", true, true, none)
	if !slices.Contains(kde, "kdialog") || slices.Contains(kde, "zenity") || !slices.Contains(kde, "libnotify") || !slices.Contains(kde, "iproute") {
		t.Fatalf("fedora kde: %v", kde)
	}
}

func TestPowerDelay(t *testing.T) {
	now := time.Date(2026, 11, 25, 9, 55, 0, 0, time.UTC)
	for _, c := range []struct {
		m    int
		sent time.Time
		want int
	}{
		{0, now.Add(-4 * time.Minute), 0}, // now stays now
		{5, time.Time{}, 5},               // older server without a send time
		{5, now.Add(-4 * time.Minute), 1}, // 4 of 5 minutes passed waiting for the check in
		{5, now.Add(-9 * time.Minute), 1}, // overdue: still one minute warning
		{30, now.Add(-10 * time.Minute), 20},
	} {
		if got := powerDelay(c.m, c.sent, now); got != c.want {
			t.Errorf("powerDelay(%d, -%v) = %d, want %d", c.m, now.Sub(c.sent), got, c.want)
		}
	}
}

func TestMaskSecrets(t *testing.T) {
	var v any
	json.Unmarshal([]byte(`{"issuer":"https://accounts.google.com","client_secret":"s3cret","nested":[{"password":"x","name":"n"}],"empty_secret":"",
		"scripts":[{"name":"s","body":"curl -H 'Authorization: abc'"}],"http":"http://bob:pw123@proxy:3128","wifi":{"psk":"wpa"},"api_key":"k1","otp_seed":["a"]}`), &v)
	b, _ := json.Marshal(maskSecrets(v))
	s := string(b)
	for _, leak := range []string{"s3cret", `"password":"x"`, "Authorization", "pw123", "wpa", "k1", `"a"`} {
		if strings.Contains(s, leak) {
			t.Fatalf("leaked %q: %s", leak, s)
		}
	}
	if !strings.Contains(s, "accounts.google.com") || !strings.Contains(s, `"name":"n"`) || !strings.Contains(s, "proxy:3128") {
		t.Fatalf("masked: %s", s)
	}
}

func TestCertInfo(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Corp Root"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	p := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	info := certInfo([]api.Certificate{{Name: "corp", PEM: p}, {Name: "broken", PEM: "nope"}})
	if len(info) != 1 || info[0].Subject != "CN=Corp Root" || len(info[0].SHA256) != 64 {
		t.Fatalf("cert info: %+v", info)
	}
}

func TestScreenLockFiles(t *testing.T) {
	if !strings.Contains(kdeLockFile(300), "[Daemon][$i]") || !strings.Contains(kdeLockFile(300), "Timeout=5") {
		t.Fatal(kdeLockFile(300))
	}
	if !strings.Contains(kdeLockFile(30), "Timeout=1") {
		t.Fatal("KDE needs at least one minute")
	}
	if !strings.Contains(xfceLockFile(600), `name="delay" type="int" value="10" locked="*"`) {
		t.Fatal(xfceLockFile(600))
	}
	set, locks := dconfLockFiles(300)
	for _, k := range []string{"org/gnome/desktop/session", "org/cinnamon/desktop/screensaver", "org/mate/screensaver"} {
		if !strings.Contains(set, k) || !strings.Contains(locks, "/"+k) {
			t.Fatalf("%s missing", k)
		}
	}
	if !strings.Contains(swayLockFile(300), "exec swayidle -w timeout 300 'swaylock -f -c 000000'") {
		t.Fatal(swayLockFile(300))
	}
	strict := screenLockPolicy{seconds: 300, manageLogin: true, hideUsers: true}
	if l := lightdmFile(strict); !strings.Contains(l, "greeter-hide-users=true") || !strings.Contains(l, "autologin-user=\n") {
		t.Fatal(l)
	}
	if l := lightdmFile(screenLockPolicy{seconds: 300, allowAutologin: true}); strings.Contains(l, "autologin-user") || strings.Contains(l, "hide-users") {
		t.Fatal(l)
	}
	if s := sddmFile(strict); !strings.Contains(s, "[Autologin]\nUser=\n") || !strings.Contains(s, "RememberLastUser=false") {
		t.Fatal(s)
	}
	if _, g := gdmFiles(); !strings.Contains(g, "disable-user-list=true") {
		t.Fatal(g)
	}
}

func TestINI(t *testing.T) {
	gdm := "# GDM\n[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=bob\n\n[security]\n"
	out := setINIValue(gdm, "daemon", "AutomaticLoginEnable", "false")
	if iniValue(out, "daemon", "AutomaticLoginEnable") != "false" || iniValue(out, "daemon", "AutomaticLogin") != "bob" || !strings.Contains(out, "[security]") {
		t.Fatalf("set existing: %q", out)
	}
	out = setINIValue("[security]\n", "daemon", "AutomaticLoginEnable", "false")
	if iniValue(out, "daemon", "AutomaticLoginEnable") != "false" {
		t.Fatalf("add section: %q", out)
	}
	out = setINIValue("[daemon]\nWaylandEnable=false\n[security]\n", "daemon", "AutomaticLoginEnable", "false")
	if iniValue(out, "daemon", "AutomaticLoginEnable") != "false" || iniValue(out, "security", "AutomaticLoginEnable") != "" {
		t.Fatalf("add key in section: %q", out)
	}
}

func TestScreenLockPolicyOptIn(t *testing.T) {
	compose := func(payload string) screenLockPolicy {
		t.Helper()
		pol, st := api.Compose([]api.Declaration{{Identifier: "s", Type: api.TypeScreenLock, Payload: []byte(payload)}})
		if !st[0].Valid {
			t.Fatalf("%s: %v", payload, st[0].Reasons)
		}
		return (&Agent{pol: pol}).screenLockPolicy()
	}
	// existing declarations leave the login manager alone
	if p := compose(`{"idle_seconds":300}`); p.manageLogin || !p.allowAutologin || p.hideUsers {
		t.Fatalf("legacy declaration manages the login screen: %+v", p)
	}
	if p := compose(`{"idle_seconds":300,"hide_users":true}`); !p.manageLogin || !p.hideUsers || !p.allowAutologin {
		t.Fatalf("hide_users alone must not touch autologin: %+v", p)
	}
	if p := compose(`{"idle_seconds":300,"allow_autologin":false}`); !p.manageLogin || p.allowAutologin || p.hideUsers {
		t.Fatalf("allow_autologin false: %+v", p)
	}
	for _, v := range []string{"true", "True", "1", "yes"} {
		if !truthy(v) {
			t.Errorf("%q is true for GLib", v)
		}
	}
	if truthy("false") || truthy("") {
		t.Error("false values")
	}
}

func TestIdleLockRespectsRemediation(t *testing.T) {
	a := &Agent{}
	a.pol.ScreenLockSeconds = 300
	a.pol.Compliance.Level, a.pol.Compliance.Remediate = 1, true
	snap := func() { p := a.pol; a.polView.Store(&p) }
	snap()
	if !a.remediatesScreenLock() {
		t.Fatal("remediation on")
	}
	a.pol.Compliance.Exclude = []string{"desktop.screenlock"}
	snap()
	if a.remediatesScreenLock() {
		t.Fatal("excluded check must not be enforced")
	}
	a.pol.Compliance.Exclude, a.pol.Compliance.Remediate = nil, false
	snap()
	if a.remediatesScreenLock() {
		t.Fatal("remediation off must not start lockers")
	}
}

func TestStoreHelpers(t *testing.T) {
	f := flathubFilterContent([]string{"org.mozilla.firefox", "com.slack.Slack", "org.mozilla.firefox"})
	if !strings.Contains(f, "deny *\nallow runtime/*\n") || strings.Count(f, "allow app/org.mozilla.firefox") != 1 || !strings.Contains(f, "allow app/com.slack.Slack") {
		t.Fatalf("filter: %q", f)
	}
	m := installedFlatpaks([]api.FlatpakApp{{ID: "a", Installation: "bob"}, {ID: "a", Installation: "system"}, {ID: "b", Installation: "alice"}})
	if m["a"] != "system" || m["b"] != "alice" {
		t.Fatalf("installed flatpaks: %v", m)
	}
	src := api.AppSource{Kind: "package", Debian: "firefox-esr", Fedora: "firefox"}
	if p := familyPackages(src, "debian"); len(p) != 1 || p[0] != "firefox-esr" {
		t.Fatal(p)
	}
	var st store
	st.jobs = map[string]*appJob{}
	if !st.start("x", "install") || st.start("x", "install") {
		t.Fatal("a running job must not start twice")
	}
	st.finish("x", errors.New("boom"))
	if j := st.job("x"); j == nil || j.Err != "boom" || !st.start("x", "install") {
		t.Fatal("a failed job can start again")
	}
}

func TestAppRepoFiles(t *testing.T) {
	r := api.Repository{Name: "netbird", URL: "https://pkgs.netbird.io/yum/", Key: "KEY", SignedMetadata: true}
	kn, k, sn, src := (&host{family: "fedora"}).repoFiles("limdm-app-", r)
	if kn != "RPM-GPG-KEY-limdm-app-netbird" || k != "KEY" || sn != "limdm-app-netbird.repo" ||
		!strings.Contains(src, "gpgcheck=0\nrepo_gpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-limdm-app-netbird") {
		t.Fatalf("fedora: %s %s\n%s", kn, sn, src)
	}
	r = api.Repository{Name: "mullvad", URL: "https://repository.mullvad.net/deb/stable", Suites: "stable", Components: "main", Key: "KEY"}
	kn, _, sn, src = (&host{family: "debian"}).repoFiles("limdm-app-", r)
	if kn != "limdm-app-mullvad.asc" || sn != "limdm-app-mullvad.sources" || !strings.Contains(src, "Signed-By: /etc/apt/keyrings/limdm-app-mullvad.asc") {
		t.Fatalf("debian: %s %s\n%s", kn, sn, src)
	}
	// declarations must not delete the catalog's repository files
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "limdm-app-mullvad.sources"), nil, 0o644)
	os.WriteFile(filepath.Join(dir, "limdm-old.sources"), nil, 0o644)
	if _, err := syncManaged(dir, "limdm-", ".sources", nil, appRepoFiles(dir)...); err != nil {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(left) != 1 || filepath.Base(left[0]) != "limdm-app-mullvad.sources" {
		t.Fatalf("left: %v", left)
	}
}

func TestParsePeople(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\ngdm:x:42:42::/var/lib/gdm:/sbin/nologin\nmalte:x:1000:1000::/home/malte:/bin/zsh\nsvc:x:1001:1001::/:/usr/sbin/nologin\nnobody:x:65534:65534::/:/bin/false\nanna:x:1002:1002::/home/anna:/bin/bash\n"
	if got := parsePeople(passwd); !slices.Equal(got, []string{"malte", "anna"}) {
		t.Fatalf("people: %v", got)
	}
}

func TestConsoleSession(t *testing.T) {
	props := `Id=3
Name=malte
User=1000
Type=tty
Class=user
State=active
Remote=no
LockedHint=no
Audit=3

Id=4
Name=malte
User=1000
Type=wayland
Class=user
State=active
Remote=no
LockedHint=yes
Audit=4

Id=5
Name=anna
User=1001
Type=unspecified
Class=user
State=active
Remote=yes
LockedHint=no
Audit=5

Id=6
Name=root
User=0
Type=tty
Class=user
State=active
Remote=yes

Id=c1
Name=gdm
User=42
Type=wayland
Class=greeter
State=online

Id=7
Name=malte
User=1000
Type=unspecified
Class=manager
State=active`
	got := map[string]bool{}
	for _, l := range parseSessions(props) {
		got[l.ID] = consoleSession(l)
	}
	want := map[string]bool{"3": true, "4": false, "5": true, "6": false, "c1": false, "7": false}
	if !maps.Equal(got, want) {
		t.Fatalf("console sessions: %v", got)
	}
	if s := parseSessions(props); !s[1].Locked || s[1].Type != "wayland" || s[1].Audit != "4" {
		t.Fatalf("parsed: %+v", s[1])
	}
	if s := parseSessions("Id=9\nDesktop=GNOME\n"); len(s) != 1 || s[0].Desktop != "GNOME" {
		t.Fatalf("desktop: %+v", s)
	}
}

func TestRemoteLockTrust(t *testing.T) {
	// only desktops whose shell honours logind's lock request skip the
	// agent's locker; LockedHint and process names are not trusted (F11)
	for d, want := range map[string]bool{"GNOME": true, "ubuntu:GNOME": true, "KDE": true, "plasma": true, "sway": false, "i3": false, "": false, "Hyprland": false} {
		if logindLocks(d) != want {
			t.Errorf("logindLocks(%q) = %v", d, !want)
		}
	}
	if trustedExe("self", map[string]bool{"i3lock": true}) {
		t.Error("the test binary is no trusted locker")
	}
}

func TestScriptInterpreter(t *testing.T) {
	for body, want := range map[string]string{
		"echo hi":                           "/bin/sh",
		"#!/bin/bash -e\necho hi":           "/bin/bash -e",
		"#!/usr/bin/env python3\r\nprint()": "/usr/bin/env python3",
		"#!\necho":                          "/bin/sh",
	} {
		if got := strings.Join(scriptInterpreter(body), " "); got != want {
			t.Errorf("%q: %q", body, got)
		}
	}
}

func TestVerifyCommand(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	a := &Agent{cfg: Config{DeviceID: "d1"}}
	c := api.Command{ID: 7, Type: "lock", CreatedAt: time.Now().Truncate(time.Microsecond)}
	if a.verifyCommand(c) != nil {
		t.Fatal("before a key is pinned commands run as before")
	}
	a.state.CommandKey = hex.EncodeToString(pub)
	if a.verifyCommand(c) == nil {
		t.Fatal("unsigned command accepted after pinning")
	}
	c.Signature = api.SignCommand(key, "d1", c)
	if err := a.verifyCommand(c); err != nil {
		t.Fatal(err)
	}
	c.Payload = "rm -rf /"
	if a.verifyCommand(c) == nil {
		t.Fatal("changed payload accepted")
	}
}

// A rollover signed by the pinned key moves the agent to the new key and
// keeps the old one for the grace period; a forged one changes nothing.
func TestCommandKeyRollover(t *testing.T) {
	oldPub, oldKey, _ := ed25519.GenerateKey(nil)
	newPub, newKey, _ := ed25519.GenerateKey(nil)
	_, evilKey, _ := ed25519.GenerateKey(nil)
	newHex := hex.EncodeToString(newPub)
	a := &Agent{cfg: Config{DeviceID: "d1"}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.state.CommandKey = hex.EncodeToString(oldPub)
	sign := func(k ed25519.PrivateKey) *api.KeyRollover {
		return &api.KeyRollover{Key: newHex, Signature: hex.EncodeToString(ed25519.Sign(k, api.RolloverSigned(newHex)))}
	}

	a.pinCommandKey(newHex, nil) // no rollover record
	a.pinCommandKey(newHex, sign(evilKey))
	forged := sign(oldKey)
	forged.Key = hex.EncodeToString(make([]byte, 32)) // record for another key than offered
	a.pinCommandKey(newHex, forged)
	if a.state.CommandKey != hex.EncodeToString(oldPub) || a.state.CommandKeyPrev != "" {
		t.Fatal("a forged rollover changed the pinned key")
	}

	a.pinCommandKey(newHex, sign(oldKey))
	if a.state.CommandKey != newHex || a.state.CommandKeyPrev != hex.EncodeToString(oldPub) {
		t.Fatal("valid rollover not adopted")
	}
	c := api.Command{ID: 1, Type: "lock", CreatedAt: time.Now().Truncate(time.Microsecond)}
	c.Signature = api.SignCommand(newKey, "d1", c)
	if err := a.verifyCommand(c); err != nil {
		t.Fatal(err)
	}
	c.Signature = api.SignCommand(oldKey, "d1", c)
	if err := a.verifyCommand(c); err != nil {
		t.Fatalf("old key refused during the grace period: %v", err)
	}
	a.state.CommandKeyPrevUntil = time.Now().Add(-time.Minute)
	if a.verifyCommand(c) == nil {
		t.Fatal("old key accepted after the grace period")
	}
	c.Signature = api.SignCommand(evilKey, "d1", c)
	a.state.CommandKeyPrevUntil = time.Now().Add(time.Hour)
	if a.verifyCommand(c) == nil {
		t.Fatal("command of an unknown key accepted")
	}
}

// The enrolled agent verifies the server with standard TLS verification
// against the device CAs, host included, and new CAs apply at once.
func TestSwapTransportRoots(t *testing.T) {
	mkCA := func() (*x509.Certificate, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		c, _ := x509.ParseCertificate(der)
		return c, key
	}
	oldCA, _ := mkCA()
	newCA, newKey := mkCA()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, newCA, &k.PublicKey, newKey)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}
	srv.StartTLS()
	defer srv.Close()

	tc, err := pinnedTLS(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: oldCA.Raw}), srv.URL)
	if err != nil || tc.InsecureSkipVerify || tc.RootCAs == nil {
		t.Fatalf("pinnedTLS: %v skip=%v", err, tc.InsecureSkipVerify)
	}
	c := newClient(tc)
	if resp, err := c.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("certificate of an untrusted CA accepted")
	}
	pool := x509.NewCertPool()
	pool.AddCert(oldCA)
	pool.AddCert(newCA)
	c.Transport.(*swapTransport).setRoots(pool)
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("new CA after the swap: %v", err)
	}
	resp.Body.Close()
	if resp, err := c.Get(strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)); err == nil {
		resp.Body.Close()
		t.Fatal("wrong host accepted")
	}
}

func TestParseCAs(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mk := func(isCA bool) string {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotAfter: time.Now().Add(time.Hour),
			IsCA: isCA, BasicConstraintsValid: true}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	if certs, err := parseCAs([]byte(mk(true) + mk(true))); err != nil || len(certs) != 2 {
		t.Fatalf("two CAs: %d %v", len(certs), err)
	}
	if _, err := parseCAs([]byte(mk(true) + mk(false))); err == nil {
		t.Fatal("a leaf certificate in the bundle was accepted")
	}
	if _, err := parseCAs([]byte("junk")); err == nil {
		t.Fatal("empty bundle accepted")
	}
}

func TestInventoryHelpers(t *testing.T) {
	for in, want := range map[string]string{"To be filled by O.E.M.": "", "Default string": "", " LENOVO ": "LENOVO", "0123456789": "", "PF47M7M1": "PF47M7M1"} {
		if got := cleanDMI(in); got != want {
			t.Errorf("cleanDMI(%q) = %q", in, got)
		}
	}
	for in, want := range map[string]string{"labwc:wlroots": "labwc", "X-Cinnamon": "Cinnamon", "Hyprland": "Hyprland", "XFCE": "Xfce", "Pantheon": "Pantheon"} {
		if got := desktopName(in); got != want {
			t.Errorf("desktopName(%q) = %q", in, got)
		}
	}
}

func TestPollWait(t *testing.T) {
	if w := pollWait(0); w < time.Minute || w > time.Minute+10*time.Second {
		t.Fatalf("normal: %v", w)
	}
	if w := pollWait(10); w < 5*time.Minute || w > 5*time.Minute+10*time.Second {
		t.Fatalf("backoff capped at five minutes: %v", w)
	}
}

func TestParseSnapList(t *testing.T) {
	out := "Name      Version   Rev    Tracking       Publisher   Notes\ncore22    20240111  1122   latest/stable  canonical✓  base\nfirefox   125.0     4173   latest/stable  mozilla*    -\n"
	got := parseSnapList(out)
	if len(got) != 2 || got[0].Notes != "base" || got[1].Name != "firefox" || got[1].Publisher != "mozilla" || got[1].Notes != "" {
		t.Fatalf("%+v", got)
	}
}

func TestWeakSSH(t *testing.T) {
	evals := map[string]map[string]string{
		"":         {"ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com", "macs": "hmac-sha2-256-etm@openssh.com", "kexalgorithms": "curve25519-sha256"},
		" for bob": {"ciphers": "aes128-cbc", "macs": "hmac-sha1", "kexalgorithms": "curve25519-sha256"},
	}
	bad := weakSSH(evals, map[string]int{"ssh_host_rsa_key.pub": 2048, "ssh_host_ed25519_key.pub": 256, "ssh_host_dsa_key.pub": 1024})
	want := []string{"ciphers: aes128-cbc", "host key ssh_host_dsa_key.pub: DSA", "host key ssh_host_rsa_key.pub: RSA 2048 bits", "macs: hmac-sha1"}
	if !slices.Equal(bad, want) {
		t.Fatalf("%v", bad)
	}
	if len(weakSSH(map[string]map[string]string{"": evals[""]}, map[string]int{"ssh_host_rsa_key.pub": 4096})) != 0 {
		t.Fatal("strong configuration flagged")
	}
}

func TestEncryptionParsing(t *testing.T) {
	st := "/dev/mapper/luks-1 is active and is in use.\n  type:    LUKS2\n  cipher:  aes-xts-plain64\n"
	if got := cryptTypeOf(st); got != "LUKS2" {
		t.Fatal(got)
	}
	if got := cryptTypeOf("  type:    PLAIN\n"); got != "plain dm-crypt" {
		t.Fatal(got)
	}
	if got := cryptTypeOf("  type:    LUKS2\n  hw-opal: yes\n"); got != "LUKS2 hw-opal" {
		t.Fatal(got)
	}
	show := "Label: none  uuid: 1\n\tTotal devices 2 FS bytes used 1.00GiB\n\tdevid    1 size 100.00GiB used 2.00GiB path /dev/mapper/a\n\tdevid    2 size 100.00GiB used 2.00GiB path /dev/sdb1\n"
	if d := btrfsDevices(show); !slices.Equal(d, []string{"/dev/mapper/a", "/dev/sdb1"}) {
		t.Fatal(d)
	}
}

func TestSSOOfflineGrace(t *testing.T) {
	p := pamPolicy{Login: api.Login{Enabled: true, LocalPassword: true, ReverifyHours: 24}}
	now := time.Now()
	for _, c := range []struct {
		age     time.Duration
		offline bool
		due     bool
	}{{time.Hour, false, false}, {30 * time.Hour, false, true}, {30 * time.Hour, true, false}, {24*time.Hour + 73*time.Hour, true, true}} {
		if got := ssoDueAt(p, now.Add(-c.age), true, c.offline, now); got != c.due {
			t.Errorf("age %v offline %v: due %v", c.age, c.offline, got)
		}
	}
	if !ssoDueAt(p, time.Time{}, false, true, now) {
		t.Fatal("never confirmed: due even offline")
	}
	p.OfflineGraceHours = 10
	if !ssoDueAt(p, now.Add(-35*time.Hour), true, true, now) {
		t.Fatal("configured grace of 10 hours exceeded")
	}
}

func TestSessionModeLocks(t *testing.T) {
	p := pamPolicy{Login: api.Login{Enabled: true, Mode: "session", LocalPassword: true, ReverifyHours: 720, GraceHours: 168}}
	now := time.Now()
	day := 24 * time.Hour
	if !sessionLock(p, time.Time{}, false, true, now) {
		t.Fatal("an account never bound needs SSO at the login screen")
	}
	for _, c := range []struct {
		age     time.Duration
		offline bool
		lock    bool
		due     bool
	}{
		{10 * day, false, false, false},
		{31 * day, false, false, true}, // due: the desktop app asks, the password still works
		{40 * day, false, true, true},  // beyond the grace period while online: locked
		{40 * day, true, false, true},  // offline (holiday): never locked for the overdue confirmation
		{365 * day, true, false, true}, // also after a long time offline
	} {
		if got := sessionLock(p, now.Add(-c.age), true, c.offline, now); got != c.lock {
			t.Errorf("age %v offline %v: lock %v", c.age, c.offline, got)
		}
		if got := sessionDue(p, now.Add(-c.age), now); got != c.due {
			t.Errorf("age %v: due %v", c.age, got)
		}
	}
}

func TestDistributionFamilies(t *testing.T) {
	for osr, want := range map[string]string{
		"ID=centos\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"9\"": "fedora",
		"ID=rocky\nID_LIKE=\"rhel centos fedora\"":             "fedora",
		"ID=arch":                      "arch",
		"ID=manjaro\nID_LIKE=arch":     "arch",
		"ID=endeavouros\nID_LIKE=arch": "arch",
		"ID=alpine\nVERSION_ID=3.21.0": "alpine",
		"ID=ubuntu\nID_LIKE=debian":    "debian",
		"ID=nixos":                     "",
	} {
		if got := familyOf(parseOSRelease(osr)); got != want {
			t.Errorf("%q: %q", osr, got)
		}
	}
	p, _ := parsePacmanQ("linux 6.12.1.arch1-1\nfirefox 133.0-1\n", nil)
	if len(p) != 2 || p[1].Name != "firefox" || p[1].Version != "133.0-1" {
		t.Fatalf("pacman: %+v", p)
	}
	a, _ := parseApkInfo("musl-1.2.5-r8\nlibcrypto3-3.3.2-r4\nalpine-base-3.21.0-r0\n", nil)
	if len(a) != 3 || a[1].Name != "libcrypto3" || a[1].Version != "3.3.2-r4" || a[2].Name != "alpine-base" {
		t.Fatalf("apk: %+v", a)
	}
	for fam, want := range map[string]string{"debian": "deb", "fedora": "rpm", "arch": "pkg.tar.zst", "alpine": "apk"} {
		if f := api.PackageName("1.0.0", "amd64", packageFormat(fam)); !api.PackageRe.MatchString(f) || !strings.HasSuffix(f, want) {
			t.Errorf("%s: %s", fam, f)
		}
	}
}

func TestCountDnfSecurity(t *testing.T) {
	dnf4 := "FEDORA-2024-1a2b3c Important/Sec. openssl-3.1.4-1.fc39.x86_64\nRHSA-2024:1234 Moderate/Sec. curl-8.0-1.el9.x86_64\n"
	dnf5 := "Name               Type     Severity  Package                           Issued\nFEDORA-2025-ab12cd security Important openssl-3.2.2-1.fc41.x86_64 2025-01-02 10:00:00\n"
	if countDnfLines(dnf4) != 2 || countDnfLines(dnf5) != 1 || countDnfLines("") != 0 {
		t.Fatalf("dnf4 %d dnf5 %d", countDnfLines(dnf4), countDnfLines(dnf5))
	}
	if countDnfLines("FEDORA-EPEL-2024-5fd0ca6e30 Important/Sec. nginx-1.26-1.el9.x86_64\n") != 1 {
		t.Error("EPEL advisory not counted")
	}
	checkUpdate := "\nkernel.x86_64    6.11.4-301.fc41    updates\nopenssl.x86_64   1:3.2.2-9.fc41     updates\nObsoleting Packages\n"
	if countDnfPackages(checkUpdate) != 2 {
		t.Errorf("check-update count %d", countDnfPackages(checkUpdate))
	}
}

func TestDisableDeb822KeepsCommentStanzas(t *testing.T) {
	in := "## Note: generated by cloud-init\n##\n\nTypes: deb\r\nURIs: http://archive.ubuntu.com/ubuntu\r\nSuites: noble\r\n \nTypes: deb\nURIs: http://security.ubuntu.com/ubuntu\nEnabled: yes\n"
	out := disableRepoContent("ubuntu.sources", in)
	if strings.Count(out, "Enabled: no") != 2 || strings.Contains(out, "Enabled: yes") || strings.Contains(out, "##\nEnabled") {
		t.Fatalf("deb822 disable:\n%s", out)
	}
}

func TestTTYName(t *testing.T) {
	for nr, want := range map[string]string{"1025": "tty1", "34816": "pts/0", "34821": "pts/5", "0": "", "1088": ""} {
		if got := ttyName(nr); got != want {
			t.Errorf("%s: %q want %q", nr, got, want)
		}
	}
}

func TestEventRepeatsAreDropped(t *testing.T) {
	a := &Agent{log: slog.New(slog.DiscardHandler)}
	a.event("software stores read only: %v", true)
	a.event("software stores read only: %v", true)
	a.event("software stores read only: %v", false)
	a.event("tamper: unit stopped")
	a.event("tamper: unit stopped")
	if n := len(a.pendingEvents()); n != 4 {
		t.Fatalf("queued %d events, want 4 (one repeat dropped, tamper always kept): %v", n, a.pendingEvents())
	}
	a.lastSeen["software stores read only: true"] = time.Now().Add(-eventRepeat - time.Minute)
	a.event("software stores read only: %v", true)
	if n := len(a.pendingEvents()); n != 5 {
		t.Fatalf("a repeat after the window must be sent again, queued %d", n)
	}
}
