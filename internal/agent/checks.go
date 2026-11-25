package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

const (
	pass = "pass"
	fail = "fail"
	na   = "na"
)

// check is one entry of the compliance catalog. Checks with a kv map belong to
// a drop-in group (sysctl, sshd, modprobe): their fix writes one managed file
// covering every active check of that group, so exclusions are honoured.
type check struct {
	ID, Title string
	Level     int
	Refs      api.Refs
	Group     string            // sysctl | sshd | modprobe
	KV        map[string]string // desired values for the group
	Run       func(a *Agent) (status, detail string)
	Fix       func(a *Agent) error
}

// Framework references. BSI: IT-Grundschutz-Kompendium modules; CIS: recommendation
// titles shared by the Ubuntu, Debian and RHEL family benchmarks; ISO: 27001:2022 Annex A.
const (
	bsiClient  = "SYS.2.1"
	bsiLinux   = "SYS.2.3"
	bsiPatch   = "OPS.1.1.3"
	bsiLog     = "OPS.1.1.5"
	bsiCrypto  = "CON.1"
	bsiIAM     = "ORP.4"
	bsiNTP     = "OPS.1.2.6"
	bsiLinuxSv = "SYS.1.3"
)

func refs(bsi, iso []string, cis ...string) api.Refs { return api.Refs{BSI: bsi, ISO: iso, CIS: cis} }
func l(s ...string) []string                         { return s }

var catalog = []check{
	{ID: "agent.osquery", Title: "osquery inventory source installed", Level: 1,
		Refs: refs(l(bsiClient), l("A.5.9", "A.8.9")),
		Run: func(a *Agent) (string, string) {
			if v := osqueryVersion(); v != "" {
				return pass, "osquery " + v
			}
			return fail, "osquery missing, inventory incomplete (installed by the agent, retried hourly)"
		}},
	{ID: "os.supported", Title: "Operating system version is supported", Level: 1,
		Refs: refs(l(bsiClient, bsiPatch), l("A.8.8"), "Ensure updates, patches, and additional security software are installed"),
		Run:  runOSSupported},
	{ID: "updates.auto", Title: "Automatic updates are declared", Level: 1,
		Refs: refs(l(bsiClient, bsiPatch), l("A.8.8", "A.8.32")),
		Run: func(a *Agent) (string, string) {
			if m := a.pol.Updates.Mode; m == "" || m == "off" {
				return fail, "updates mode is off or not declared"
			}
			return pass, "mode " + a.pol.Updates.Mode + ", window " + a.pol.Updates.Window
		}},
	{ID: "updates.security", Title: "Security updates are installed", Level: 1,
		Refs: refs(l(bsiClient, bsiLinux, bsiPatch), l("A.8.8"), "Ensure updates, patches, and additional security software are installed"),
		Run:  runSecurityUpdates},
	{ID: "updates.reboot", Title: "No pending reboot older than 7 days", Level: 1,
		Refs: refs(l(bsiPatch), l("A.8.8")),
		Run:  runRebootPending},
	{ID: "disk.encryption", Title: "System disk is encrypted (LUKS)", Level: 1,
		Refs: refs(l(bsiClient, bsiCrypto), l("A.8.1", "A.8.24", "A.7.10")),
		Run:  runDiskEncryption},
	{ID: "firewall.active", Title: "Host firewall is active", Level: 1,
		Refs: refs(l(bsiClient, bsiLinux), l("A.8.20"), "Ensure a single firewall configuration utility is in use", "Ensure ufw/firewalld service is enabled"),
		Run:  runFirewall, Fix: fixFirewall},
	{ID: "mac.enabled", Title: "Mandatory access control is enabled (AppArmor/SELinux)", Level: 1,
		Refs: refs(l(bsiLinux, bsiLinuxSv), l("A.8.7", "A.8.9"), "Ensure AppArmor/SELinux is installed and enabled"),
		Run:  runMACEnabled},
	{ID: "mac.enforcing", Title: "Mandatory access control is enforcing", Level: 2,
		Refs: refs(l(bsiLinux, bsiLinuxSv), l("A.8.7", "A.8.9"), "Ensure all AppArmor profiles are enforcing", "Ensure the SELinux mode is enforcing"),
		Run:  runMACEnforcing},
	{ID: "disk.recovery", Title: "Disk encryption recovery keys are escrowed", Level: 1,
		Refs: refs(l(bsiCrypto), l("A.8.24", "A.8.13")),
		Run:  runRecoveryEscrow},
	{ID: "boot.password", Title: "Boot loader is password protected", Level: 1,
		Refs: refs(l(bsiClient, bsiLinux), l("A.8.2", "A.8.9"), "Ensure bootloader password is set", "Ensure permissions on bootloader config are configured"),
		Run:  runBootPassword},
	{ID: "boot.secureboot", Title: "Secure Boot is enabled", Level: 2,
		Refs: refs(l(bsiClient), l("A.8.1", "A.8.9")),
		Run:  runSecureBoot},

	{ID: "kernel.aslr", Title: "Full ASLR is enabled", Level: 1, Group: "sysctl",
		KV:   map[string]string{"kernel.randomize_va_space": "2"},
		Refs: refs(l(bsiLinux), l("A.8.9"), "Ensure address space layout randomization is enabled")},
	{ID: "kernel.ptrace", Title: "ptrace is restricted", Level: 1, Group: "sysctl",
		KV:   map[string]string{"kernel.yama.ptrace_scope": "1"},
		Refs: refs(l(bsiLinux), l("A.8.9"), "Ensure ptrace_scope is restricted")},
	{ID: "kernel.coredumps", Title: "Core dumps are restricted", Level: 1, Group: "sysctl",
		KV:   map[string]string{"fs.suid_dumpable": "0"},
		Refs: refs(l(bsiLinux), l("A.8.9", "A.8.12"), "Ensure core dumps are restricted")},
	{ID: "kernel.dmesg", Title: "Kernel log and pointers are restricted", Level: 2, Group: "sysctl",
		KV:   map[string]string{"kernel.dmesg_restrict": "1", "kernel.kptr_restrict": "2"},
		Refs: refs(l(bsiLinux), l("A.8.9"))},
	{ID: "net.forwarding", Title: "IP forwarding is disabled", Level: 1, Group: "sysctl",
		KV:   map[string]string{"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"},
		Refs: refs(l(bsiLinux), l("A.8.20"), "Ensure ip forwarding is disabled")},
	{ID: "net.redirects", Title: "ICMP redirects and source routing are disabled", Level: 1, Group: "sysctl",
		KV: map[string]string{
			"net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.conf.default.accept_redirects": "0",
			"net.ipv6.conf.all.accept_redirects": "0", "net.ipv6.conf.default.accept_redirects": "0",
			"net.ipv4.conf.all.send_redirects": "0", "net.ipv4.conf.default.send_redirects": "0",
			"net.ipv4.conf.all.secure_redirects": "0", "net.ipv4.conf.default.secure_redirects": "0",
			"net.ipv4.conf.all.accept_source_route": "0", "net.ipv4.conf.default.accept_source_route": "0",
			"net.ipv6.conf.all.accept_source_route": "0", "net.ipv6.conf.default.accept_source_route": "0",
		},
		Refs: refs(l(bsiLinux), l("A.8.20"), "Ensure ICMP redirects are not accepted", "Ensure packet redirect sending is disabled", "Ensure source routed packets are not accepted")},
	{ID: "net.tcp", Title: "TCP SYN cookies, martian logging, broadcast ICMP ignored", Level: 1, Group: "sysctl",
		KV: map[string]string{
			"net.ipv4.tcp_syncookies": "1", "net.ipv4.icmp_echo_ignore_broadcasts": "1",
			"net.ipv4.icmp_ignore_bogus_error_responses": "1",
			"net.ipv4.conf.all.log_martians":             "1", "net.ipv4.conf.default.log_martians": "1",
		},
		Refs: refs(l(bsiLinux), l("A.8.20"), "Ensure tcp syn cookies is enabled", "Ensure suspicious packets are logged", "Ensure broadcast ICMP requests are ignored")},

	{ID: "modules.filesystems", Title: "Unused filesystems are disabled", Level: 1, Group: "modprobe",
		KV:   map[string]string{"cramfs": "", "freevxfs": "", "hfs": "", "hfsplus": "", "jffs2": ""},
		Refs: refs(l(bsiLinux), l("A.8.9"), "Ensure cramfs, freevxfs, hfs, hfsplus, jffs2 kernel modules are not available")},
	{ID: "modules.udf", Title: "UDF is disabled", Level: 2, Group: "modprobe",
		KV:   map[string]string{"udf": ""},
		Refs: refs(l(bsiLinux), l("A.8.9"), "Ensure udf kernel module is not available")},
	{ID: "modules.usbstorage", Title: "USB mass storage is blocked", Level: 2, Group: "modprobe",
		KV:   map[string]string{"usb-storage": "", "uas": ""},
		Refs: refs(l(bsiClient, bsiLinux), l("A.7.10", "A.8.12"), "Ensure usb-storage kernel module is not available")},
	{ID: "modules.netproto", Title: "Unused network protocols are disabled", Level: 2, Group: "modprobe",
		KV:   map[string]string{"dccp": "", "sctp": "", "rds": "", "tipc": ""},
		Refs: refs(l(bsiLinux), l("A.8.20"), "Ensure dccp, sctp, rds, tipc kernel modules are not available")},

	{ID: "ssh.baseline", Title: "SSH server is hardened", Level: 1, Group: "sshd",
		KV: map[string]string{
			"permitrootlogin": "no", "permitemptypasswords": "no", "maxauthtries": "<=4", "logingracetime": "<=60",
			"hostbasedauthentication": "no", "ignorerhosts": "yes", "permituserenvironment": "no", "x11forwarding": "no",
			"clientaliveinterval": "<=300", "clientalivecountmax": "<=3",
		},
		Refs: refs(l(bsiLinux, bsiLinuxSv), l("A.8.5", "A.8.20"), "Ensure sshd PermitRootLogin is disabled", "Ensure sshd PermitEmptyPasswords is disabled",
			"Ensure sshd MaxAuthTries is configured", "Ensure sshd LoginGraceTime is configured", "Ensure sshd HostbasedAuthentication is disabled",
			"Ensure sshd IgnoreRhosts is enabled", "Ensure sshd PermitUserEnvironment is disabled", "Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured")},
	{ID: "ssh.crypto", Title: "SSH offers no weak algorithms or host keys", Level: 1,
		Refs: refs(l(bsiLinux, bsiLinuxSv, bsiCrypto), l("A.8.24"), "Ensure sshd Ciphers are configured", "Ensure sshd MACs are configured", "Ensure sshd KexAlgorithms is configured"),
		Run:  runSSHCrypto, Fix: fixSSHCrypto},
	{ID: "ssh.strict", Title: "SSH allows keys only and no forwarding", Level: 2, Group: "sshd",
		KV:   map[string]string{"passwordauthentication": "no", "kbdinteractiveauthentication": "no", "allowtcpforwarding": "no"},
		Refs: refs(l(bsiLinux, bsiLinuxSv), l("A.8.5"), "Ensure sshd DisableForwarding is enabled")},

	{ID: "accounts.empty_passwords", Title: "No accounts with empty passwords", Level: 1,
		Refs: refs(l(bsiIAM, bsiLinux), l("A.5.17", "A.8.5"), "Ensure /etc/shadow password fields are not empty"),
		Run:  runEmptyPasswords, Fix: fixEmptyPasswords},
	{ID: "accounts.uid0", Title: "Only root has UID 0", Level: 1,
		Refs: refs(l(bsiIAM, bsiLinux), l("A.8.2"), "Ensure root is the only UID 0 account"),
		Run:  runUID0},
	{ID: "accounts.admins", Title: "Admin rights only for centrally approved users", Level: 1,
		Refs: refs(l(bsiIAM, bsiClient), l("A.5.15", "A.5.18", "A.8.2")),
		Run:  runAdmins},
	{ID: "accounts.pwquality", Title: "Password quality (minimum length 14)", Level: 1,
		Refs: refs(l(bsiIAM), l("A.5.17"), "Ensure password length is configured", "Ensure password complexity is configured"),
		Run:  runPWQuality, Fix: fixPWQuality},
	{ID: "auth.sso", Title: "Desktop login through the central identity provider", Level: 1,
		Refs: refs(l(bsiIAM), l("A.5.16", "A.8.5")),
		Run:  runSSO, Fix: func(a *Agent) error { return a.installPAM() }},

	{ID: "time.sync", Title: "Time synchronisation is active", Level: 1,
		Refs: refs(l(bsiNTP, bsiLog), l("A.8.17"), "Ensure a single time synchronization daemon is in use"),
		Run:  runTimeSync, Fix: fixTimeSync},
	{ID: "logging.journald", Title: "System log is persistent", Level: 1,
		Refs: refs(l(bsiLog, bsiLinux), l("A.8.15"), "Ensure journald is configured to write logfiles to persistent disk"),
		Run:  runJournald, Fix: fixJournald},
	{ID: "logging.sudo", Title: "sudo logs and uses a PTY", Level: 1,
		Refs: refs(l(bsiLog, bsiIAM), l("A.8.2", "A.8.15"), "Ensure sudo commands use pty", "Ensure sudo log file exists"),
		Run:  runSudoLog, Fix: fixSudoLog},
	{ID: "logging.auditd", Title: "auditd is active with LiMDM rules", Level: 2,
		Refs: refs(l(bsiLog, bsiLinux), l("A.8.15", "A.8.16"), "Ensure auditd service is enabled and active", "Ensure changes to system administration scope (sudoers) is collected",
			"Ensure events that modify user/group information are collected", "Ensure events that modify date and time information are collected", "Ensure kernel module loading unloading and modification is collected"),
		Run: runAuditd, Fix: fixAuditd},
	{ID: "desktop.screenlock", Title: "Screen lock on idle is enforced", Level: 1,
		Refs: refs(l(bsiClient), l("A.8.1", "A.7.7"), "Ensure GDM screen locks when the user is idle", "Ensure GDM screen locks cannot be overridden"),
		Run:  runScreenLock, Fix: fixScreenLock},
}

// evaluate runs every check of the policy level, remediates when allowed and
// re-checks so the report reflects the state after remediation.
func (a *Agent) evaluate() []api.CheckResult {
	p := a.pol.Compliance
	var out []api.CheckResult
	for _, c := range catalog {
		if c.Level > p.Level {
			continue
		}
		r := api.CheckResult{ID: c.ID, Title: c.Title, Level: c.Level, Refs: c.Refs}
		if slices.Contains(p.Exclude, c.ID) {
			r.Status, r.Detail = "excepted", "documented exception (risk accepted)"
			out = append(out, r)
			continue
		}
		r.Status, r.Detail = a.runCheck(c)
		if r.Status == fail && p.Remediate {
			if fix := a.fixFor(c); fix != nil {
				if err := fix(a); err != nil {
					r.Detail += "; remediation failed: " + err.Error()
					a.event("remediation %s failed: %v", c.ID, err)
				} else if r.Status, r.Detail = a.runCheck(c); r.Status == pass {
					r.Remediated = true
					a.event("remediated %s", c.ID)
				}
			}
		}
		if r.Status == fail && slices.Contains(p.Advisory, c.ID) {
			r.Status = "advisory" // reported, not counted against compliance
		}
		out = append(out, r)
	}
	return out
}

func (a *Agent) runCheck(c check) (string, string) {
	switch c.Group {
	case "sysctl":
		return runSysctl(c.KV)
	case "modprobe":
		return runModprobe(c.KV)
	case "sshd":
		return runSSHD(c.KV)
	}
	return c.Run(a)
}

func (a *Agent) fixFor(c check) func(*Agent) error {
	switch c.Group {
	case "sysctl":
		return fixSysctl
	case "modprobe":
		return fixModprobe
	case "sshd":
		return fixSSHD
	}
	return c.Fix
}

// groupKV merges desired values of all active, non excluded checks of a group.
func (a *Agent) groupKV(group string) map[string]string {
	kv := map[string]string{}
	for _, c := range catalog {
		if c.Group == group && c.Level <= a.pol.Compliance.Level && !slices.Contains(a.pol.Compliance.Exclude, c.ID) {
			for k, v := range c.KV {
				kv[k] = v
			}
		}
	}
	return kv
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

const managedHeader = "# Managed by LiMDM. Local changes are overwritten.\n"

// ---- sysctl ----

func sysctlPath(key string) string { return "/proc/sys/" + strings.ReplaceAll(key, ".", "/") }

func runSysctl(kv map[string]string) (string, string) {
	var bad []string
	for _, k := range sortedKeys(kv) {
		p := sysctlPath(k)
		if !exists(p) {
			continue // e.g. IPv6 disabled
		}
		if got := readTrim(p); got != kv[k] {
			bad = append(bad, fmt.Sprintf("%s=%s (want %s)", k, got, kv[k]))
		}
	}
	if len(bad) > 0 {
		return fail, strings.Join(bad, ", ")
	}
	return pass, ""
}

func fixSysctl(a *Agent) error {
	kv := a.groupKV("sysctl")
	var b strings.Builder
	b.WriteString(managedHeader)
	for _, k := range sortedKeys(kv) {
		fmt.Fprintf(&b, "%s = %s\n", k, kv[k])
	}
	const f = "/etc/sysctl.d/60-limdm-hardening.conf"
	if _, err := writeIfChanged(f, b.String(), 0o644); err != nil {
		return err
	}
	// -e ignores keys missing on this kernel; apply only our file.
	_, err := sh("sysctl", "-q", "-e", "-p", f)
	if a.groupHas("sysctl", "fs.suid_dumpable") {
		_, e1 := writeIfChanged("/etc/security/limits.d/60-limdm.conf", managedHeader+"* hard core 0\n", 0o644)
		_, e2 := writeIfChanged("/etc/systemd/coredump.conf.d/60-limdm.conf", managedHeader+"[Coredump]\nStorage=none\nProcessSizeMax=0\n", 0o644)
		err = errors.Join(err, e1, e2)
	}
	return err
}

func (a *Agent) groupHas(group, key string) bool {
	_, ok := a.groupKV(group)[key]
	return ok
}

// ---- kernel modules ----

func runModprobe(kv map[string]string) (string, string) {
	loaded := readFile("/proc/modules")
	var bad []string
	for _, m := range sortedKeys(kv) {
		name := strings.ReplaceAll(m, "-", "_")
		if strings.Contains("\n"+loaded, "\n"+name+" ") {
			bad = append(bad, m+" loaded")
			continue
		}
		s, err := sh("modprobe", "-n", "-v", m)
		if err != nil && strings.Contains(s, "FATAL: Module") && strings.Contains(s, "not found") {
			continue // module does not exist on this kernel
		}
		if !strings.Contains(s, "install /bin/false") && !strings.Contains(s, "install /bin/true") &&
			!strings.Contains(s, "install /usr/bin/false") && !strings.Contains(s, "install /usr/bin/true") {
			bad = append(bad, m+" loadable")
		}
	}
	if len(bad) > 0 {
		return fail, strings.Join(bad, ", ")
	}
	return pass, ""
}

func fixModprobe(a *Agent) error {
	kv := a.groupKV("modprobe")
	var b strings.Builder
	b.WriteString(managedHeader)
	for _, m := range sortedKeys(kv) {
		fmt.Fprintf(&b, "install %s /bin/false\nblacklist %s\n", m, m)
	}
	if _, err := writeIfChanged("/etc/modprobe.d/60-limdm-hardening.conf", b.String(), 0o644); err != nil {
		return err
	}
	var errs []error
	for _, m := range sortedKeys(kv) {
		if strings.Contains("\n"+readFile("/proc/modules"), "\n"+strings.ReplaceAll(m, "-", "_")+" ") {
			if _, err := sh("modprobe", "-r", m); err != nil {
				errs = append(errs, fmt.Errorf("%s in use, unloads after reboot", m))
			}
		}
	}
	return errors.Join(errs...)
}

// ---- sshd ----

const sshDropin = "/etc/ssh/sshd_config.d/01-limdm.conf" // sshd uses the first value found, so sort first

func sshdBinary() string {
	for _, p := range []string{"/usr/sbin/sshd", "/usr/bin/sshd"} {
		if exists(p) {
			return p
		}
	}
	return ""
}

func runSSHD(kv map[string]string) (string, string) {
	bin := sshdBinary()
	if bin == "" {
		return na, "no SSH server installed"
	}
	// missing with socket activation (Ubuntu 24.04), sshd -T needs it
	if err := os.MkdirAll("/run/sshd", 0o755); err != nil { //nolint:gosec // sshd privilege separation dir
		return fail, err.Error()
	}
	evals, err := sshdEffective(bin)
	if err != nil {
		return fail, err.Error()
	}
	var bad []string
	for _, k := range sortedKeys(kv) {
		for spec, got := range evals { // every Match context has to comply
			if !sshValueOK(got[k], kv[k]) {
				bad = append(bad, fmt.Sprintf("%s=%s (want %s)%s", k, got[k], kv[k], spec))
				break
			}
		}
	}
	if len(bad) > 0 {
		return fail, strings.Join(bad, ", ")
	}
	return pass, ""
}

// sshdEffective evaluates the effective server configuration for the global
// context and, so Match blocks count, for a connection as root and as each
// person with a local account (up to five). Keys are lower case.
func sshdEffective(bin string) (map[string]map[string]string, error) {
	specs := []string{""}
	users := append([]string{"root"}, peopleAccounts()...)
	for _, u := range users[:min(len(users), 6)] {
		specs = append(specs, "user="+u+",host=client.invalid,addr=203.0.113.1,laddr=127.0.0.1,lport=22")
	}
	res := map[string]map[string]string{}
	for _, spec := range specs {
		args := []string{"-T"}
		if spec != "" {
			args = append(args, "-C", spec)
		}
		out, err := sh(bin, args...)
		if err != nil {
			if spec == "" {
				return nil, fmt.Errorf("sshd -T: %w", err)
			}
			continue // an older sshd without -C support: the global evaluation stands
		}
		got := map[string]string{}
		for _, line := range strings.Split(out, "\n") {
			if k, v, ok := strings.Cut(line, " "); ok {
				got[strings.ToLower(k)] = strings.ToLower(strings.TrimSpace(v))
			}
		}
		label := ""
		if spec != "" {
			label = " for " + strings.TrimPrefix(strings.Split(spec, ",")[0], "user=")
		}
		res[label] = got
	}
	return res, nil
}

// weakSSH lists weak algorithms the server offers and weak host keys.
func weakSSH(evals map[string]map[string]string, hostKeys map[string]int) []string {
	weak := map[string][]string{
		"ciphers":           {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256", "rijndael-cbc@lysator.liu.se"},
		"macs":              {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96", "umac-64@openssh.com", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "hmac-sha1-96-etm@openssh.com", "umac-64-etm@openssh.com"},
		"kexalgorithms":     {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"},
		"hostkeyalgorithms": {"ssh-dss", "ssh-rsa", "ssh-dss-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com"},
	}
	seen := map[string]bool{}
	var bad []string
	for _, got := range evals {
		for _, key := range sortedKeys(map[string]string{"ciphers": "", "macs": "", "kexalgorithms": "", "hostkeyalgorithms": ""}) {
			for _, alg := range strings.Split(got[key], ",") {
				if slices.Contains(weak[key], alg) && !seen[key+alg] {
					seen[key+alg] = true
					bad = append(bad, key+": "+alg)
				}
			}
		}
	}
	for f, bits := range hostKeys {
		switch {
		case strings.Contains(f, "_dsa_"):
			bad = append(bad, "host key "+f+": DSA")
		case strings.Contains(f, "_rsa_") && bits < 3072:
			bad = append(bad, fmt.Sprintf("host key %s: RSA %d bits", f, bits))
		}
	}
	slices.Sort(bad)
	return bad
}

// sshHostKeys reads the size of each host key with ssh-keygen.
func sshHostKeys() map[string]int {
	keys := map[string]int{}
	files, _ := filepath.Glob("/etc/ssh/ssh_host_*_key.pub")
	for _, f := range files {
		if out, err := sh("ssh-keygen", "-l", "-f", f); err == nil {
			if fields := strings.Fields(out); len(fields) > 0 {
				keys[filepath.Base(f)], _ = strconv.Atoi(fields[0])
			}
		}
	}
	return keys
}

func runSSHCrypto(a *Agent) (string, string) {
	bin := sshdBinary()
	if bin == "" {
		return na, "no SSH server installed"
	}
	_ = os.MkdirAll("/run/sshd", 0o755) //nolint:gosec // sshd privilege separation dir
	evals, err := sshdEffective(bin)
	if err != nil {
		return fail, err.Error()
	}
	if bad := weakSSH(evals, sshHostKeys()); len(bad) > 0 {
		return fail, strings.Join(bad, "; ")
	}
	return pass, ""
}

const sshCryptoDropin = "/etc/ssh/sshd_config.d/02-limdm-crypto.conf"

// fixSSHCrypto offers only strong algorithms this OpenSSH supports; weak
// host keys are reported, not replaced (clients would see a new key).
func fixSSHCrypto(a *Agent) error {
	bin := sshdBinary()
	if bin == "" || !strings.Contains(readFile("/etc/ssh/sshd_config"), "sshd_config.d/*.conf") {
		return nil
	}
	strong := map[string][]string{
		"Ciphers":       {"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"},
		"MACs":          {"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "umac-128-etm@openssh.com"},
		"KexAlgorithms": {"sntrup761x25519-sha512@openssh.com", "mlkem768x25519-sha256", "curve25519-sha256", "curve25519-sha256@libssh.org", "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group-exchange-sha256"},
	}
	query := map[string]string{"Ciphers": "cipher", "MACs": "mac", "KexAlgorithms": "kex"}
	var b strings.Builder
	b.WriteString(managedHeader)
	for _, k := range []string{"Ciphers", "KexAlgorithms", "MACs"} {
		out, err := sh("ssh", "-Q", query[k])
		if err != nil {
			return err
		}
		have := strings.Fields(out)
		var use []string
		for _, alg := range strong[k] {
			if slices.Contains(have, alg) {
				use = append(use, alg)
			}
		}
		if len(use) == 0 {
			return fmt.Errorf("no strong %s supported", k)
		}
		fmt.Fprintf(&b, "%s %s\n", k, strings.Join(use, ","))
	}
	old, readErr := os.ReadFile(sshCryptoDropin)
	changed, err := writeIfChanged(sshCryptoDropin, b.String(), 0o600)
	if err != nil || !changed {
		return err
	}
	if _, err := sh(bin, "-t"); err != nil {
		if readErr == nil {
			err = errors.Join(err, os.WriteFile(sshCryptoDropin, old, 0o600)) //nolint:gosec // constant path, restoring the previous file
		} else {
			err = errors.Join(err, os.Remove(sshCryptoDropin))
		}
		return err
	}
	for _, unit := range []string{"ssh", "sshd"} {
		_, _ = sh("systemctl", "try-reload-or-restart", unit)
	}
	return nil
}

func sshValueOK(got, want string) bool {
	if n, ok := strings.CutPrefix(want, "<="); ok {
		g, err1 := strconv.Atoi(got)
		w, _ := strconv.Atoi(n)
		return err1 == nil && g > 0 && g <= w
	}
	return got == want
}

func sshWanted(v string) string {
	if n, ok := strings.CutPrefix(v, "<="); ok {
		return n
	}
	return v
}

func fixSSHD(a *Agent) error {
	bin := sshdBinary()
	if bin == "" {
		return nil
	}
	if !strings.Contains(readFile("/etc/ssh/sshd_config"), "sshd_config.d/*.conf") {
		return errors.New("sshd_config does not include sshd_config.d")
	}
	kv := a.groupKV("sshd")
	var b strings.Builder
	b.WriteString(managedHeader)
	for _, k := range sortedKeys(kv) {
		fmt.Fprintf(&b, "%s %s\n", k, sshWanted(kv[k]))
	}
	old, readErr := os.ReadFile(sshDropin)
	changed, err := writeIfChanged(sshDropin, b.String(), 0o600)
	if err != nil || !changed {
		return err
	}
	if _, err := sh(bin, "-t"); err != nil {
		// never leave sshd with a config it cannot load
		if readErr == nil {
			err = errors.Join(err, os.WriteFile(sshDropin, old, 0o600)) //nolint:gosec // constant path, restoring the previous file
		} else {
			err = errors.Join(err, os.Remove(sshDropin))
		}
		return err
	}
	for _, unit := range []string{"ssh", "sshd"} {
		_, _ = sh("systemctl", "try-reload-or-restart", unit) // only one of ssh/sshd exists
	}
	return nil
}

// ---- individual checks ----

func runOSSupported(a *Agent) (string, string) {
	min, ok := a.pol.MinOSVersion[a.host.ID]
	if !ok {
		return pass, a.host.Name + " (no minimum version declared)"
	}
	if api.CompareVersions(a.host.Version, min) < 0 {
		return fail, fmt.Sprintf("%s < Mindestversion %s", a.host.Version, min)
	}
	return pass, a.host.Name
}

func runSecurityUpdates(a *Agent) (string, string) {
	all, sec, err := a.host.pendingUpdates()
	if err != nil {
		return fail, "update status unknown: " + err.Error()
	}
	detail := fmt.Sprintf("%d security updates, %d updates in total pending", sec, all)
	if sec == 0 {
		return pass, detail
	}
	// Patch process working: pending updates are tolerated until the next window run.
	if m := a.pol.Updates.Mode; m != "" && m != "off" && time.Since(a.state.LastUpdateRun) < 48*time.Hour {
		return pass, detail + ", installed in the next maintenance window"
	}
	return fail, detail
}

func runRebootPending(a *Agent) (string, string) {
	if !a.host.rebootRequired() {
		a.state.RebootSince = time.Time{}
		return pass, ""
	}
	if a.state.RebootSince.IsZero() {
		a.state.RebootSince = time.Now()
	}
	since := time.Since(a.state.RebootSince)
	detail := fmt.Sprintf("reboot required for %s", since.Round(time.Hour))
	if since > 7*24*time.Hour {
		return fail, detail
	}
	return pass, detail
}

func runDiskEncryption(a *Agent) (string, string) {
	if de := a.pol.Extra.DiskEncryption; de != nil && de.RequireAll {
		var open, ok []string
		for _, v := range nativeVolumes() {
			switch {
			case de.Excluded(v.Mount):
			case v.Encrypted:
				ok = append(ok, v.Mount)
			default:
				open = append(open, v.Mount)
			}
		}
		if len(open) > 0 {
			return fail, "not encrypted: " + strings.Join(open, ", ") + " (reinstall with LUKS or exclude the mount point)"
		}
		if len(ok) == 0 {
			return fail, "no encrypted volume found"
		}
		return pass, "on LUKS: " + strings.Join(ok, ", ")
	}
	src, err := sh("findmnt", "-n", "-o", "SOURCE", "/")
	if err != nil {
		return fail, err.Error()
	}
	src = strings.TrimSpace(src)
	if i := strings.Index(src, "["); i > 0 { // btrfs subvolume: /dev/mapper/x[/root]
		src = src[:i]
	}
	out, err := sh("lsblk", "-s", "-n", "-o", "TYPE", src)
	if err != nil {
		return fail, err.Error()
	}
	if slices.Contains(strings.Fields(out), "crypt") {
		return pass, src + " is on LUKS"
	}
	return fail, src + " is not encrypted (reinstall with LUKS required)"
}

func runFirewall(a *Agent) (string, string) {
	switch {
	case unitActive("firewalld"):
		return pass, "firewalld active"
	case hasCmd("ufw"):
		if out, _ := sh("ufw", "status"); strings.Contains(out, "Status: active") {
			return pass, "ufw active"
		}
	}
	if out, err := sh("nft", "list", "ruleset"); err == nil && nftDropsInput(out) {
		return pass, "nftables input chain with policy drop"
	}
	return fail, "no host firewall dropping unsolicited inbound traffic"
}

// nftInputDrop matches a base chain on the input hook whose default policy is drop.
// A chain with policy accept filters nothing by default, however many rules it has.
var nftInputDrop = regexp.MustCompile(`type filter hook input priority [^;]+; policy drop;`)

func nftDropsInput(ruleset string) bool { return nftInputDrop.MatchString(ruleset) }

func fixFirewall(a *Agent) error {
	if !a.pol.Firewall.Enforce {
		return errors.New("firewall enforce is off")
	}
	return a.applyFirewall()
}

func (a *Agent) applyFirewall() error {
	if a.host.family == "debian" {
		// A hand written nftables ruleset (VPN clients such as NetBird add their own
		// tables) must not be overlaid with ufw; report instead of clobbering it.
		if unitActive("nftables") && !hasCmd("ufw") {
			return errors.New("nftables is managed locally: add an input chain with policy drop")
		}
		if !hasCmd("ufw") {
			if err := a.host.install("ufw"); err != nil {
				return err
			}
		}
		// allow rules first so enabling never cuts an active SSH session
		for _, rule := range a.pol.Firewall.Allow {
			if _, err := sh("ufw", "allow", rule); err != nil {
				return err
			}
		}
		if _, err := sh("ufw", "default", "deny", "incoming"); err != nil {
			return err
		}
		_, err := sh("ufw", "--force", "enable")
		return err
	}
	if !hasCmd("firewall-cmd") {
		if err := a.host.install("firewalld"); err != nil {
			return err
		}
	}
	if _, err := sh("systemctl", "enable", "--now", "firewalld"); err != nil {
		return err
	}
	for _, rule := range a.pol.Firewall.Allow {
		port := strings.Replace(rule, ":", "-", 1)
		if _, err := sh("firewall-cmd", "--permanent", "--add-port="+port); err != nil {
			return err
		}
	}
	_, err := sh("firewall-cmd", "--reload")
	return err
}

func runMACEnabled(a *Agent) (string, string) {
	if readTrim("/sys/module/apparmor/parameters/enabled") == "Y" {
		return pass, "AppArmor enabled"
	}
	if exists("/sys/fs/selinux/enforce") {
		return pass, "SELinux enabled"
	}
	return fail, "neither AppArmor nor SELinux enabled"
}

func runMACEnforcing(a *Agent) (string, string) {
	if exists("/sys/fs/selinux/enforce") {
		if readTrim("/sys/fs/selinux/enforce") == "1" {
			return pass, "SELinux enforcing"
		}
		return fail, "SELinux permissive"
	}
	if readTrim("/sys/module/apparmor/parameters/enabled") == "Y" && hasCmd("aa-status") {
		out, _ := sh("aa-status", "--complaining")
		if n, _ := strconv.Atoi(strings.TrimSpace(out)); n > 0 {
			return fail, fmt.Sprintf("%d AppArmor profiles in complain mode", n)
		}
		return pass, "AppArmor profiles enforcing"
	}
	return fail, "no mandatory access control enabled"
}

func runSecureBoot(a *Agent) (string, string) {
	b, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err != nil {
		if !exists("/sys/firmware/efi") {
			return fail, "not booted with UEFI"
		}
		return fail, "Secure Boot state unreadable"
	}
	if len(b) >= 5 && b[4] == 1 {
		return pass, "Secure Boot is enabled"
	}
	return fail, "Secure Boot disabled"
}

func shadowEntries() [][]string {
	var out [][]string
	for _, line := range strings.Split(readFile("/etc/shadow"), "\n") {
		if f := strings.Split(line, ":"); len(f) >= 2 && f[0] != "" {
			out = append(out, f)
		}
	}
	return out
}

func runEmptyPasswords(a *Agent) (string, string) {
	var bad []string
	for _, f := range shadowEntries() {
		if f[1] == "" {
			bad = append(bad, f[0])
		}
	}
	if len(bad) > 0 {
		return fail, "empty password: " + strings.Join(bad, ", ")
	}
	return pass, ""
}

func fixEmptyPasswords(a *Agent) error {
	var errs []error
	for _, f := range shadowEntries() {
		if f[1] == "" {
			if _, err := sh("passwd", "-l", f[0]); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func runUID0(a *Agent) (string, string) {
	var bad []string
	for _, line := range strings.Split(readFile("/etc/passwd"), "\n") {
		if f := strings.Split(line, ":"); len(f) > 3 && f[2] == "0" && f[0] != "root" {
			bad = append(bad, f[0])
		}
	}
	if len(bad) > 0 {
		return fail, "other UID 0 accounts: " + strings.Join(bad, ", ")
	}
	return pass, ""
}

func groupMembers(group string) []string {
	for _, line := range strings.Split(readFile("/etc/group"), "\n") {
		if f := strings.Split(line, ":"); len(f) == 4 && f[0] == group && f[3] != "" {
			return strings.Split(f[3], ",")
		}
	}
	return nil
}

// runAdmins only applies once users are managed centrally; before that local admins are expected.
func runAdmins(a *Agent) (string, string) {
	if !a.pol.Login.Enabled {
		return na, "central login not declared"
	}
	allowed := map[string]bool{}
	for _, u := range a.users {
		if u.Admin {
			allowed[u.Username] = true
		}
	}
	var extra []string
	for _, m := range groupMembers(a.host.adminGroup()) {
		if !allowed[m] {
			extra = append(extra, m)
		}
	}
	if len(extra) > 0 {
		return fail, "unapproved admins in " + a.host.adminGroup() + ": " + strings.Join(extra, ", ")
	}
	return pass, ""
}

func pwqualityValue(key string) string {
	files, _ := filepath.Glob("/etc/security/pwquality.conf.d/*.conf")
	files = append([]string{"/etc/security/pwquality.conf"}, files...)
	val := ""
	for _, f := range files {
		for _, line := range strings.Split(readFile(f), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == key && !strings.HasPrefix(strings.TrimSpace(k), "#") {
				val = strings.TrimSpace(v)
			}
		}
	}
	return val
}

func pamHasPWQuality() bool {
	for _, f := range []string{"/etc/pam.d/common-password", "/etc/pam.d/system-auth"} {
		if strings.Contains(readFile(f), "pam_pwquality.so") {
			return true
		}
	}
	return false
}

func runPWQuality(a *Agent) (string, string) {
	if !pamHasPWQuality() {
		return fail, "pam_pwquality not in the PAM stack"
	}
	n, _ := strconv.Atoi(pwqualityValue("minlen"))
	if n < 14 {
		return fail, fmt.Sprintf("minlen=%d (want >= 14)", n)
	}
	return pass, fmt.Sprintf("minlen=%d", n)
}

func fixPWQuality(a *Agent) error {
	if a.host.family == "debian" && !a.host.isInstalled("libpam-pwquality") {
		if err := a.host.install("libpam-pwquality"); err != nil {
			return err
		}
	}
	_, err := writeIfChanged("/etc/security/pwquality.conf.d/60-limdm.conf",
		managedHeader+"minlen = 14\nminclass = 3\nmaxrepeat = 3\ndictcheck = 1\nenforce_for_root\n", 0o644)
	return err
}

func runSSO(a *Agent) (string, string) {
	if !a.pol.Login.Enabled {
		return na, "desktop login not declared"
	}
	if !pamActive() {
		return fail, "PAM integration missing"
	}
	return pass, fmt.Sprintf("%s, %d users", a.pol.Login.Issuer, len(a.users))
}

func runTimeSync(a *Agent) (string, string) {
	for _, u := range []string{"chronyd", "chrony", "systemd-timesyncd"} {
		if unitActive(u) {
			return pass, u + " active"
		}
	}
	return fail, "no time synchronisation service active"
}

func fixTimeSync(a *Agent) error {
	if a.host.isInstalled("chrony") {
		unit := "chrony"
		if a.host.family == "fedora" {
			unit = "chronyd"
		}
		_, err := sh("systemctl", "enable", "--now", unit)
		return err
	}
	if a.host.family == "debian" {
		if err := a.host.install("systemd-timesyncd"); err != nil {
			return err
		}
		_, err := sh("systemctl", "enable", "--now", "systemd-timesyncd")
		return err
	}
	if err := a.host.install("chrony"); err != nil {
		return err
	}
	_, err := sh("systemctl", "enable", "--now", "chronyd")
	return err
}

func runJournald(a *Agent) (string, string) {
	if st, err := os.Stat("/var/log/journal"); err == nil && st.IsDir() {
		return pass, "journald persistent"
	}
	if unitActive("rsyslog") {
		return pass, "rsyslog active"
	}
	return fail, "logs are volatile only"
}

func fixJournald(a *Agent) error {
	if _, err := writeIfChanged("/etc/systemd/journald.conf.d/60-limdm.conf", managedHeader+"[Journal]\nStorage=persistent\n", 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll("/var/log/journal", 0o2755); err != nil { //nolint:gosec // systemd default mode
		return err
	}
	if _, err := sh("systemd-tmpfiles", "--create", "--prefix", "/var/log/journal"); err != nil {
		return err
	}
	_, err := sh("systemctl", "restart", "systemd-journald")
	return err
}

// Only active Defaults lines count; "!use_pty" disables it.
var (
	sudoUsePTY  = regexp.MustCompile(`(?m)^\s*Defaults\b[^\n#]*[\s,]use_pty\b`)
	sudoNoPTY   = regexp.MustCompile(`(?m)^\s*Defaults\b[^\n#]*!\s*use_pty\b`)
	sudoLogfile = regexp.MustCompile(`(?m)^\s*Defaults\b[^\n#]*[\s,]logfile\s*=`)
)

func sudoDefaults() string {
	s := readFile("/etc/sudoers")
	files, _ := filepath.Glob("/etc/sudoers.d/*")
	for _, f := range files {
		s += "\n" + readFile(f)
	}
	return s
}

func runSudoLog(a *Agent) (string, string) {
	s := sudoDefaults()
	var miss []string
	if !sudoUsePTY.MatchString(s) || sudoNoPTY.MatchString(s) {
		miss = append(miss, "use_pty")
	}
	if !sudoLogfile.MatchString(s) {
		miss = append(miss, "logfile")
	}
	if len(miss) > 0 {
		return fail, "missing: " + strings.Join(miss, ", ")
	}
	return pass, ""
}

func fixSudoLog(a *Agent) error {
	const f = "/etc/sudoers.d/60-limdm"
	content := managedHeader + "Defaults use_pty\nDefaults logfile=\"/var/log/sudo.log\"\n"
	tmp := f + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o440); err != nil { //nolint:gosec // sudoers mode, readable by root only
		return err
	}
	if _, err := sh("visudo", "-c", "-f", tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, f)
}

var auditRules = []struct{ path, rule string }{
	{"", "-w /etc/sudoers -p wa -k scope"},
	{"/etc/sudoers.d", "-w /etc/sudoers.d -p wa -k scope"},
	{"", "-w /etc/passwd -p wa -k identity"},
	{"", "-w /etc/group -p wa -k identity"},
	{"", "-w /etc/shadow -p wa -k identity"},
	{"", "-w /etc/gshadow -p wa -k identity"},
	{"/etc/security/opasswd", "-w /etc/security/opasswd -p wa -k identity"},
	{"", "-w /etc/hosts -p wa -k system-locale"},
	{"/etc/apparmor", "-w /etc/apparmor/ -p wa -k MAC-policy"},
	{"/etc/selinux", "-w /etc/selinux/ -p wa -k MAC-policy"},
	{"/var/log/lastlog", "-w /var/log/lastlog -p wa -k logins"},
	{"/etc/limdm", "-w /etc/limdm/ -p wa -k limdm"},
	{"", "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change"},
	{"", "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale"},
	{"", "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_modules"},
}

const auditRulesFile = "/etc/audit/rules.d/60-limdm.rules"

func runAuditd(a *Agent) (string, string) {
	if !unitActive("auditd") {
		return fail, "auditd not active"
	}
	if !exists(auditRulesFile) {
		return fail, "LiMDM audit rules missing"
	}
	if out, err := sh("auditctl", "-l"); err != nil || !strings.Contains(out, "key=identity") {
		return fail, "LiMDM audit rules not loaded"
	}
	return pass, "auditd active"
}

func fixAuditd(a *Agent) error {
	pkg := "auditd"
	if a.host.family == "fedora" {
		pkg = "audit"
	}
	if !a.host.isInstalled(pkg) {
		if err := a.host.install(pkg); err != nil {
			return err
		}
	}
	var b strings.Builder
	b.WriteString(managedHeader)
	for _, r := range auditRules {
		if r.path == "" || exists(r.path) {
			b.WriteString(r.rule + "\n")
		}
	}
	if _, err := writeIfChanged(auditRulesFile, b.String(), 0o640); err != nil {
		return err
	}
	if _, err := sh("systemctl", "enable", "--now", "auditd"); err != nil {
		return err
	}
	_, err := sh("augenrules", "--load")
	return err
}
