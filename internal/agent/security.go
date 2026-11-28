package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// ---- polkit ----

const polkitDir = "/etc/polkit-1/rules.d"

// polkitJS renders one rule. Every value was validated against strict patterns,
// strconv.Quote yields valid JavaScript string literals for them.
func polkitJS(r api.PolkitRule) string {
	var acts []string
	for _, a := range r.Actions {
		if p, ok := strings.CutSuffix(a, ".*"); ok {
			acts = append(acts, "action.id.indexOf("+strconv.Quote(p+".")+") == 0")
		} else {
			acts = append(acts, "action.id == "+strconv.Quote(a))
		}
	}
	cond := "(" + strings.Join(acts, " || ") + ")"
	if len(r.Groups) > 0 {
		var gs []string
		for _, g := range r.Groups {
			gs = append(gs, "subject.isInGroup("+strconv.Quote(g)+")")
		}
		cond += " && (" + strings.Join(gs, " || ") + ")"
	}
	if r.LocalActiveOnly {
		cond += " && subject.local && subject.active"
	}
	return "// " + strings.TrimSpace(managedHeader[2:]) + "\npolkit.addRule(function(action, subject) {\n\tif (" + cond +
		") {\n\t\treturn polkit.Result." + strings.ToUpper(r.Result) + ";\n\t}\n});\n"
}

func applyPolkit(rules []api.PolkitRule) error {
	if _, err := os.Stat(polkitDir); err != nil {
		if len(rules) == 0 {
			return nil
		}
		return errors.New("polkit is not installed")
	}
	desired := map[string]string{}
	for _, r := range rules {
		desired["60-limdm-"+r.Name+".rules"] = polkitJS(r)
	}
	// the store lock rule shares the prefix and is the catalog's, not the polkit item's
	_, err := syncManaged(polkitDir, "60-limdm-", ".rules", desired, filepath.Base(storeReadOnly))
	return err // polkitd picks up changed rule files on its own
}

// ---- sudo ----

const sudoersDir = "/etc/sudoers.d"

func sudoLine(r api.SudoRule) string {
	runAs := r.RunAs
	if runAs == "" {
		runAs = "root"
	}
	tag := ""
	if r.NoPasswd {
		tag = "NOPASSWD: "
	}
	return strings.Join(r.Principals, ", ") + " ALL=(" + runAs + ") " + tag + strings.Join(r.Commands, ", ") + "\n"
}

// applySudo writes one sudoers drop in per rule (prefix 70-limdm-, the
// compliance defaults live in 60-limdm). Every new content is checked with
// visudo first; a rejected rule keeps its previous file. If the complete
// configuration fails afterwards although it was valid before, the managed
// files are restored to their previous state, so sudo keeps working.
func applySudo(s *api.Sudo) error {
	desired := map[string]string{}
	if s != nil {
		for _, r := range s.Rules {
			desired["70-limdm-"+r.Name] = managedHeader + sudoLine(r)
		}
		if s.TimestampTimeout != nil {
			desired["70-limdm-defaults"] = managedHeader + "Defaults timestamp_timeout=" + strconv.Itoa(*s.TimestampTimeout) + "\n"
		}
	}
	existing, _ := filepath.Glob(filepath.Join(sudoersDir, "70-limdm-*"))
	if len(desired) == 0 && len(existing) == 0 {
		return nil
	}
	_, baseErr := sh("visudo", "-c", "-q")
	previous := map[string]string{} // name -> content before this run ("" = did not exist)
	for _, f := range existing {
		previous[filepath.Base(f)] = readFile(f)
	}
	tmp, err := os.MkdirTemp("/run", "limdm-sudo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	var errs []error
	keep := map[string]bool{}
	for name, content := range desired {
		f := filepath.Join(tmp, name)
		if err := os.WriteFile(f, []byte(content), 0o440); err != nil { //nolint:gosec // sudoers mode
			return err
		}
		if out, err := sh("visudo", "-c", "-q", "-f", f); err != nil {
			errs = append(errs, fmt.Errorf("sudo rule %s rejected by visudo, previous version kept: %s", name, lastLines(out, 2)))
			keep[name] = true
			continue
		}
		if _, err := writeIfChanged(filepath.Join(sudoersDir, name), content, 0o440); err != nil {
			errs = append(errs, err)
		}
	}
	for name := range previous {
		if _, ok := desired[name]; !ok && !keep[name] {
			errs = append(errs, os.Remove(filepath.Join(sudoersDir, name)))
		}
	}
	if baseErr != nil {
		return errors.Join(append(errs, fmt.Errorf("sudo configuration was already invalid before LiMDM changed it: %w", baseErr))...)
	}
	if out, err := sh("visudo", "-c", "-q"); err != nil {
		for name := range desired {
			if old, ok := previous[name]; ok {
				_, _ = writeIfChanged(filepath.Join(sudoersDir, name), old, 0o440)
			} else {
				os.Remove(filepath.Join(sudoersDir, name))
			}
		}
		for name, old := range previous {
			if _, ok := desired[name]; !ok {
				_, _ = writeIfChanged(filepath.Join(sudoersDir, name), old, 0o440)
			}
		}
		errs = append(errs, fmt.Errorf("sudo configuration invalid after the change, previous state restored: %s", lastLines(out, 2)))
	}
	return errors.Join(errs...)
}

// ---- boot loader password ----

const (
	grubDebianScript = "/etc/grub.d/01_limdm_password"
	grubFedoraUser   = "/boot/grub2/user.cfg"
	grubLinuxScript  = "/etc/grub.d/10_linux"
)

func (a *Agent) applyBootloader(b *api.Bootloader) error {
	if a.host.family == "fedora" {
		// grub2-setpassword format: the superuser is always root, BLS entries stay bootable
		content := ""
		if b != nil {
			content = managedHeader + "GRUB2_PASSWORD=" + b.PasswordPBKDF2 + "\n"
		} else if !strings.HasPrefix(readFile(grubFedoraUser), managedHeader) {
			return nil // set by an administrator, not ours to remove
		}
		_, err := writeOrRemove(grubFedoraUser, content, 0o600)
		return err
	}
	if _, err := os.Stat("/etc/grub.d"); err != nil {
		if b == nil {
			return nil
		}
		return errors.New("GRUB not found (/etc/grub.d missing)")
	}
	content := ""
	if b != nil {
		content = "#!/bin/sh\n" + managedHeader + "cat <<'EOF'\nset superusers=\"" + b.Superuser + "\"\npassword_pbkdf2 " +
			b.Superuser + " " + b.PasswordPBKDF2 + "\nEOF\n"
	}
	changed, err := writeOrRemove(grubDebianScript, content, 0o700)
	if err != nil {
		return err
	}
	if b != nil && b.Unrestricted {
		// default entries stay bootable without the password; only editing and the console need it
		cur := readFile(grubLinuxScript)
		const plain = `CLASS="--class gnu-linux --class gnu --class os"`
		if strings.Contains(cur, plain) {
			if err := os.WriteFile(grubLinuxScript, []byte(strings.Replace(cur, plain, `CLASS="--class gnu-linux --class gnu --class os --unrestricted"`, 1)), 0o755); err != nil { //nolint:gosec // grub.d scripts are executable
				return err
			}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	mkconfig, cfg := grubConfig(a.host.family)
	if out, err := sh(mkconfig, "-o", cfg); err != nil {
		os.Remove(grubDebianScript) // retried on the next cycle
		return fmt.Errorf("%s: %s", mkconfig, lastLines(out, 3))
	}
	if err := os.Chmod(cfg, 0o600); err != nil { // contains the password hash
		return err
	}
	a.event("boot loader password configuration updated")
	return nil
}

// grubConfig is the config generator and its output: SUSE names them grub2.
func grubConfig(family string) (mkconfig, cfg string) {
	if family == "suse" {
		return "grub2-mkconfig", "/boot/grub2/grub.cfg"
	}
	return "grub-mkconfig", "/boot/grub/grub.cfg"
}

func runBootPassword(a *Agent) (string, string) {
	if a.host.family == "fedora" {
		if strings.Contains(readFile(grubFedoraUser), "GRUB2_PASSWORD=grub.pbkdf2.") {
			return pass, "GRUB password set in " + grubFedoraUser
		}
		return fail, "no GRUB password (declare a boot loader item)"
	}
	_, path := grubConfig(a.host.family)
	cfg := readFile(path)
	if cfg == "" {
		return na, "GRUB not used"
	}
	if strings.Contains(cfg, "password_pbkdf2 ") && strings.Contains(cfg, "set superusers=") {
		return pass, "GRUB superuser with PBKDF2 password"
	}
	return fail, "no GRUB password (declare a boot loader item)"
}

// ---- LUKS recovery key escrow ----

const escrowRequest = stateDir + "/escrow-request.json"

var userRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

type pendingKey struct {
	api.RecoveryKey
	OldKey string `json:"old_key,omitempty"` // removed from the header once the new key is escrowed
}

type luksVolume struct{ Path, UUID string }

func luksVolumes() []luksVolume {
	out, err := sh("lsblk", "-nrpo", "PATH,FSTYPE,UUID")
	if err != nil {
		return nil
	}
	var vs []luksVolume
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == 3 && f[1] == "crypto_LUKS" {
			vs = append(vs, luksVolume{f[0], strings.ToLower(f[2])})
		}
	}
	return vs
}

// withKeyFiles writes keys to a private tmpfs directory for cryptsetup.
func withKeyFiles(keys []string, fn func(files []string) error) error {
	dir, err := os.MkdirTemp("/run", "limdm-luks-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	var files []string
	for i, k := range keys {
		f := filepath.Join(dir, strconv.Itoa(i))
		if err := os.WriteFile(f, []byte(k), 0o600); err != nil {
			return err
		}
		files = append(files, f)
	}
	return fn(files)
}

// luksAddKey adds newKey using unlock and verifies the new key opens the header.
func luksAddKey(dev, unlock, newKey string) error {
	return withKeyFiles([]string{unlock, newKey}, func(f []string) error {
		if out, err := sh("cryptsetup", "luksAddKey", "--batch-mode", "--key-file", f[0], dev, f[1]); err != nil {
			return fmt.Errorf("cryptsetup luksAddKey: %s", lastLines(out, 2))
		}
		if out, err := sh("cryptsetup", "open", "--test-passphrase", "--key-file", f[1], dev); err != nil {
			return fmt.Errorf("new key does not open %s: %s", dev, lastLines(out, 2))
		}
		return nil
	})
}

func luksRemoveKey(dev, key string) error {
	return withKeyFiles([]string{key}, func(f []string) error {
		if out, err := sh("cryptsetup", "luksRemoveKey", "--batch-mode", dev, f[0]); err != nil {
			return fmt.Errorf("cryptsetup luksRemoveKey: %s", lastLines(out, 2))
		}
		return nil
	})
}

// takeEscrowRequests moves keys created by "limdm-agent recovery-key" into state.
func (a *Agent) takeEscrowRequests() {
	err := withEscrowRequests(func(ks []pendingKey) ([]pendingKey, error) {
		if len(ks) == 0 {
			return nil, nil
		}
		a.state.PendingKeys = append(a.state.PendingKeys, ks...)
		if err := a.saveStateErr(); err != nil {
			a.state.PendingKeys = a.state.PendingKeys[:len(a.state.PendingKeys)-len(ks)]
			return ks, err // keep the file: the keys exist only there
		}
		return nil, nil
	})
	if err != nil {
		a.event("escrow requests: %v", err)
	}
}

// withEscrowRequests gives exclusive access to the escrow request file, which
// the agent, the desktop socket and the recovery-key command share. fn returns
// the remaining entries; the file is replaced atomically or removed.
func withEscrowRequests(fn func([]pendingKey) ([]pendingKey, error)) error {
	lock, err := os.OpenFile(escrowRequest+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }() // closing the file releases it too
	var ks []pendingKey
	if b, err := os.ReadFile(escrowRequest); err == nil {
		if err := json.Unmarshal(b, &ks); err != nil {
			return fmt.Errorf("%s is corrupt, left in place: %w", escrowRequest, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	rest, ferr := fn(ks)
	if len(rest) == 0 {
		if err := os.Remove(escrowRequest); err != nil && !os.IsNotExist(err) {
			return errors.Join(ferr, err)
		}
		return ferr
	}
	b, err := json.Marshal(rest)
	if err != nil {
		return errors.Join(ferr, err)
	}
	_, err = writeIfChanged(escrowRequest, string(b), 0o600)
	return errors.Join(ferr, err)
}

// rotateRecovery replaces keys the server marked as viewed. The old key stays
// valid until the server confirmed the new one.
func (a *Agent) rotateRecovery(keys []api.RecoveryKey) {
	vols := luksVolumes()
	for _, k := range keys {
		if !k.Valid() || hasPending(a.state.PendingKeys, k.UUID) {
			continue
		}
		dev := ""
		for _, v := range vols {
			if v.UUID == k.UUID {
				dev = v.Path
			}
		}
		if dev == "" {
			continue
		}
		nk := api.NewRecoveryKey()
		if err := luksAddKey(dev, k.Key, nk); err != nil {
			a.problem(api.TypeDiskEncryption, "recovery key rotation for %s: %v", dev, err)
			continue
		}
		a.state.PendingKeys = append(a.state.PendingKeys, pendingKey{RecoveryKey: api.RecoveryKey{UUID: k.UUID, Device: dev, Key: nk}, OldKey: k.Key})
		a.event("recovery key for %s rotated, waiting for escrow", dev)
		a.syncNow = true
	}
}

// escrowConfirmed runs after the server stored the pending keys.
func (a *Agent) escrowConfirmed(sent []pendingKey) {
	if a.state.Escrowed == nil {
		a.state.Escrowed = map[string]time.Time{}
	}
	for _, k := range sent {
		if k.OldKey != "" && k.OldKey != k.Key {
			if err := luksRemoveKey(k.Device, k.OldKey); err != nil {
				a.event("removing previous recovery key of %s: %v", k.Device, err)
			}
		}
		a.state.Escrowed[k.UUID] = time.Now().UTC()
		a.event("recovery key for %s escrowed", k.Device)
	}
	a.bindEscrowed(sent)
	a.state.PendingKeys = a.state.PendingKeys[len(sent):]
}

func hasPending(ks []pendingKey, uuid string) bool {
	for _, k := range ks {
		if k.UUID == uuid {
			return true
		}
	}
	return false
}

// missingEscrow lists LUKS volumes without an escrowed or pending key.
func (a *Agent) missingEscrow() []luksVolume {
	var out []luksVolume
	for _, v := range luksVolumes() {
		if _, ok := a.state.Escrowed[v.UUID]; !ok && !hasPending(a.state.PendingKeys, v.UUID) {
			out = append(out, v)
		}
	}
	return out
}

func runRecoveryEscrow(a *Agent) (string, string) {
	if de := a.pol.Extra.DiskEncryption; de == nil || !de.Escrow {
		return na, "recovery key escrow not declared"
	}
	vols := luksVolumes()
	if len(vols) == 0 {
		return na, "no LUKS volumes"
	}
	if m := a.missingEscrow(); len(m) > 0 {
		var p []string
		for _, v := range m {
			p = append(p, v.Path)
		}
		return fail, "no recovery key escrowed for " + strings.Join(p, ", ") + "; the user is asked on the desktop"
	}
	return pass, strconv.Itoa(len(vols)) + " LUKS volume(s) with escrowed recovery key"
}

// notifyEscrow reminds logged in desktop users, at most once a day, to create
// a recovery key: only the user knows a current passphrase. The dialog that
// asks for it comes from the desktop helper (ensureHelpers keeps it running
// in every graphical session), which polls the socket and opens it by itself.
func (a *Agent) notifyEscrow() {
	if de := a.pol.Extra.DiskEncryption; de == nil || !de.Escrow || len(a.missingEscrow()) == 0 ||
		time.Since(a.state.EscrowNotified) < 24*time.Hour {
		return
	}
	sent := a.notifyUsers(urgent, "Disk recovery key required",
		"%s needs a recovery key for your disk encryption. A dialog asks for your disk passphrase; the LiMDM app has it on the page Disk Encryption too.", a.company())
	if sent {
		a.state.EscrowNotified = time.Now().Round(0)
	}
}

// CreateRecoveryKeys is the "recovery-key" command: it asks for the current
// passphrase of every LUKS volume without an escrowed key, adds a generated
// recovery key and hands it to the agent for escrow.
func CreateRecoveryKeys(readPass func(prompt string) (string, error), all bool) error {
	var st State
	if b, err := os.ReadFile(stateFile); err == nil {
		if err := json.Unmarshal(b, &st); err != nil {
			return fmt.Errorf("agent state: %w", err)
		}
	}
	var req []pendingKey
	if err := withEscrowRequests(func(ks []pendingKey) ([]pendingKey, error) { req = ks; return ks, nil }); err != nil {
		return err
	}
	vols := luksVolumes()
	if len(vols) == 0 {
		return errors.New("no LUKS volumes found")
	}
	done := 0
	for _, v := range vols {
		if _, ok := st.Escrowed[v.UUID]; (ok || hasPending(st.PendingKeys, v.UUID) || hasPending(req, v.UUID)) && !all {
			fmt.Printf("%s: recovery key already escrowed\n", v.Path)
			continue
		}
		pw, err := readPass(fmt.Sprintf("Current passphrase for %s: ", v.Path))
		if err != nil {
			return err
		}
		k := api.NewRecoveryKey()
		if err := luksAddKey(v.Path, pw, k); err != nil {
			return err
		}
		if err := queueEscrow(pendingKey{RecoveryKey: api.RecoveryKey{UUID: v.UUID, Device: v.Path, Key: k}}); err != nil {
			return err
		}
		done++
		fmt.Printf("%s: recovery key added\n", v.Path)
		if err := bindWithPIN(st.Declarations, v.Path, k, readPass); err != nil {
			fmt.Printf("%s: TPM binding failed: %v\n", v.Path, err)
		}
	}
	if done > 0 {
		fmt.Println("The agent sends the new keys to your IT department with its next check in. Your passphrase stays unchanged.")
		if _, err := run(10*time.Second, "systemctl", "kill", "--kill-who=main", "--signal=SIGUSR1", "limdm-agent"); err != nil {
			fmt.Println("(the agent is not running; the keys stay queued until it starts)")
		}
	}
	return nil
}
