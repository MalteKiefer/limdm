package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// TPM facts from sysfs and LUKS binding with systemd-cryptenroll. Binding
// needs a current key of the volume; the agent only holds one right after a
// recovery key was created or rotated, so volumes are bound when their
// escrow is confirmed. The recovery key slot always stays.

const (
	tpmSysfs     = "/sys/class/tpm/tpm0"
	dracutTPMCfg = "/etc/dracut.conf.d/60-limdm-tpm2.conf"
)

// tpmVersion is "2.0", "1.2" or "" without a TPM.
func tpmVersion() string {
	if !exists(tpmSysfs) {
		return ""
	}
	switch readTrim(tpmSysfs + "/tpm_version_major") {
	case "2":
		return "2.0"
	case "1":
		return "1.2"
	}
	if exists("/dev/tpmrm0") { // older kernels lack tpm_version_major; only TPM 2.0 has a resource manager
		return "2.0"
	}
	return "1.2"
}

// tpmInventory reports the TPM and the LUKS volumes bound to it.
func tpmInventory() *api.TPMInfo {
	v := tpmVersion()
	t := &api.TPMInfo{Present: v != "", Version: v}
	if v != "2.0" {
		return t
	}
	for _, vol := range luksVolumes() {
		if tpmBound(vol.Path) {
			t.LUKSBound = append(t.LUKSBound, vol.Path)
		}
	}
	return t
}

// tpmBound: the LUKS2 header carries a systemd-tpm2 token.
func tpmBound(dev string) bool {
	out, err := sh("cryptsetup", "luksDump", dev)
	return err == nil && strings.Contains(out, "systemd-tpm2")
}

// tpm2EnrollArgs builds the systemd-cryptenroll call: unlock with the key in
// keyFile, seal a new key to the PCRs and replace an earlier TPM2 slot, so a
// changed PCR list applies at the next binding.
func tpm2EnrollArgs(dev, keyFile string, b *api.TPM2Binding) []string {
	args := []string{"--unlock-key-file=" + keyFile, "--tpm2-device=auto", "--tpm2-pcrs=" + b.PCRList(), "--wipe-slot=tpm2"}
	if b.PIN {
		args = append(args, "--tpm2-with-pin=yes")
	}
	return append(args, dev)
}

// bindTPM2 enrolls the TPM for dev, unlocking with key. pin goes to
// systemd-cryptenroll in the NEWPIN environment variable, never in argv.
func bindTPM2(dev, key string, b *api.TPM2Binding, pin string) error {
	if tpmVersion() != "2.0" {
		return errors.New("no TPM 2.0 found")
	}
	if !hasCmd("systemd-cryptenroll") {
		return errors.New("systemd-cryptenroll missing (systemd 252 or newer)")
	}
	return withKeyFiles([]string{key}, func(f []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "systemd-cryptenroll", tpm2EnrollArgs(dev, f[0], b)...)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		if b.PIN {
			cmd.Env = append(cmd.Env, "NEWPIN="+pin)
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("systemd-cryptenroll %s: %s", dev, lastLines(string(out), 2))
		}
		return nil
	})
}

// ensureTPMInitrd adds dracut's tpm2-tss module, so the initrd can unseal
// the key at boot. Without dracut (initramfs-tools) the agent cannot help.
func ensureTPMInitrd() error {
	if !hasCmd("dracut") {
		return nil
	}
	changed, err := writeIfChanged(dracutTPMCfg, managedHeader+"add_dracutmodules+=\" tpm2-tss \"\n", 0o644)
	if err != nil || !changed {
		return err
	}
	if out, err := run(30*time.Minute, "dracut", "-f", "--regenerate-all"); err != nil {
		os.Remove(dracutTPMCfg) // retried with the next binding
		return fmt.Errorf("dracut: %s", lastLines(out, 2))
	}
	return nil
}

// bindEscrowed binds volumes whose new recovery key the server just stored.
// With a PIN the user binds in "limdm-agent recovery-key".
func (a *Agent) bindEscrowed(sent []pendingKey) {
	de := a.pol.Extra.DiskEncryption
	if de == nil || de.TPM2 == nil || de.TPM2.PIN || len(sent) == 0 || tpmVersion() != "2.0" {
		return
	}
	if err := ensureTPMInitrd(); err != nil {
		a.problem(api.TypeDiskEncryption, "TPM initrd: %v", err)
		return
	}
	for _, k := range sent {
		if err := bindTPM2(k.Device, k.Key, de.TPM2, ""); err != nil {
			a.problem(api.TypeDiskEncryption, "TPM binding: %v", err)
			continue
		}
		a.event("LUKS volume %s bound to the TPM (PCR %s)", k.Device, de.TPM2.PCRList())
	}
}

// bindWithPIN is the binding with a PIN, run by the user in "limdm-agent
// recovery-key" right after the new recovery key was added: only the user
// knows the PIN. Without a PIN declaration it does nothing.
func bindWithPIN(decls []api.Declaration, dev, key string, readPass func(string) (string, error)) error {
	pol, _ := api.Compose(decls)
	de := pol.Extra.DiskEncryption
	if de == nil || de.TPM2 == nil || !de.TPM2.PIN {
		return nil
	}
	pin, err := readPass("New TPM PIN for " + dev + " (asked at every boot): ")
	if err != nil {
		return err
	}
	again, err := readPass("Repeat the PIN: ")
	if err != nil {
		return err
	}
	if pin != again {
		return errors.New("the PINs differ")
	}
	if len(pin) < 6 {
		return errors.New("the PIN needs at least 6 characters")
	}
	if err := ensureTPMInitrd(); err != nil {
		return err
	}
	if err := bindTPM2(dev, key, de.TPM2, pin); err != nil {
		return err
	}
	fmt.Printf("%s: bound to the TPM, enter the PIN at boot; the recovery key keeps working\n", dev)
	return nil
}

func runTPMBinding(a *Agent) (string, string) {
	de := a.pol.Extra.DiskEncryption
	if de == nil || de.TPM2 == nil {
		return na, "TPM binding not declared"
	}
	vols := luksVolumes()
	if len(vols) == 0 {
		return na, "no LUKS volumes"
	}
	status := fail
	if !de.TPM2.Require {
		status = na // reported, not enforced
	}
	if v := tpmVersion(); v != "2.0" {
		return status, "no TPM 2.0 (" + firstNonEmpty(v, "none") + ")"
	}
	var open []string
	for _, v := range vols {
		if !tpmBound(v.Path) {
			open = append(open, v.Path)
		}
	}
	if len(open) > 0 {
		how := "bound with the next recovery key rotation or limdm-agent recovery-key --all"
		if de.TPM2.PIN {
			how = "the user binds them with sudo limdm-agent recovery-key --all"
		}
		return status, "not bound to the TPM: " + strings.Join(open, ", ") + "; " + how
	}
	return pass, strconv.Itoa(len(vols)) + " LUKS volume(s) bound to the TPM, PCR " + de.TPM2.PCRList()
}
