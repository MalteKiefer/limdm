package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/maltekiefer/limdm/internal/api"
)

// Protective actions for lost or stolen devices.
//
// lost: blocks every login, ends running sessions and shows a message. With an
// escrowed recovery key per LUKS volume the agent also removes every other key
// slot ("crypto lock"): after the next power off only IT, holding the recovery
// key, can open the disk. found lifts the login block; the user passphrase is
// set again with the recovery key (see docs/disk-encryption.md).
//
// wipe: erases the LUKS headers (cryptsetup luksErase), which makes the data
// unrecoverable, and powers off. Devices without LUKS are refused: there is
// no fast way to guarantee deletion.

const lostPrefix = "This device was reported lost and is locked by IT (LiMDM).\n"

var (
	luks2Slot = regexp.MustCompile(`(?m)^\s+(\d+): luks2`)
	luks1Slot = regexp.MustCompile(`(?m)^Key Slot (\d+): ENABLED`)
	unlocked  = regexp.MustCompile(`Key slot (\d+) unlocked`)
)

func activeSlots(dev string) ([]int, error) {
	out, err := sh("cryptsetup", "luksDump", dev)
	if err != nil {
		return nil, err
	}
	return parseSlots(out)
}

// parseSlots reads the active key slots from luksDump output (LUKS1 or LUKS2).
func parseSlots(dump string) ([]int, error) {
	re := luks2Slot
	if luks1Slot.MatchString(dump) {
		re = luks1Slot
	}
	var slots []int
	for _, m := range re.FindAllStringSubmatch(dump, -1) {
		n, _ := strconv.Atoi(m[1])
		slots = append(slots, n)
	}
	if len(slots) == 0 {
		return nil, errors.New("no key slots found in the LUKS header")
	}
	return slots, nil
}

// keepOnlyKey removes every key slot except the one key opens.
func keepOnlyKey(dev, key string) error {
	return withKeyFiles([]string{key}, func(f []string) error {
		out, err := sh("cryptsetup", "open", "--test-passphrase", "--verbose", "--key-file", f[0], dev)
		m := unlocked.FindStringSubmatch(out)
		if err != nil || m == nil {
			return fmt.Errorf("recovery key does not open %s", dev)
		}
		keep, _ := strconv.Atoi(m[1])
		slots, err := activeSlots(dev)
		if err != nil {
			return err
		}
		var errs []error
		for _, n := range slots {
			if n == keep {
				continue
			}
			if out, err := sh("cryptsetup", "luksKillSlot", "--batch-mode", "--key-file", f[0], dev, strconv.Itoa(n)); err != nil {
				errs = append(errs, fmt.Errorf("slot %d: %s", n, lastLines(out, 1)))
			}
		}
		return errors.Join(errs...)
	})
}

func (a *Agent) lostMode(payload string, attached []api.RecoveryKey) (string, error) {
	var lm api.LostMode
	if err := json.Unmarshal([]byte(payload), &lm); err != nil {
		return "", err
	}
	lm.Keys = append(lm.Keys, attached...) // sent beside the signed payload
	text := lostPrefix
	if m := strings.TrimSpace(lm.Message); m != "" {
		text += m + "\n"
	}
	if _, err := writeIfChanged(nologinFile, text, 0o644); err != nil {
		return "", err
	}
	var report []string
	if locked, err := lockPasswords(); err != nil {
		report = append(report, "locking local passwords: "+err.Error())
	} else if len(locked) > 0 {
		report = append(report, "local passwords of "+strings.Join(locked, ", ")+" locked")
	}
	// end running sessions of people; root, greeters and system users stay
	if !hasCmd("loginctl") { // without logind: end every process of people's accounts
		for _, u := range peopleAccounts() {
			if _, err := sh("pkill", "-KILL", "-u", u); err == nil {
				report = append(report, "processes of "+u+" ended")
			}
		}
	}
	for _, l := range loginSessions() {
		if l.person() {
			if _, err := sh("loginctl", "terminate-session", l.ID); err == nil {
				report = append(report, "session "+l.ID+" of "+l.User+" ended")
			}
		}
	}
	keys := map[string]string{}
	for _, k := range lm.Keys {
		if k.Valid() {
			keys[k.UUID] = k.Key
		}
	}
	var errs []error
	for _, v := range luksVolumes() {
		key, ok := keys[v.UUID]
		if !ok {
			report = append(report, v.Path+": no escrowed recovery key, key slots unchanged")
			continue
		}
		if err := keepOnlyKey(v.Path, key); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", v.Path, err))
			continue
		}
		report = append(report, v.Path+": only the recovery key opens the disk now")
	}
	a.event("lost mode activated")
	return "logins blocked\n" + strings.Join(report, "\n"), errors.Join(errs...)
}

func (a *Agent) foundMode() (string, error) {
	if !strings.HasPrefix(readFile(nologinFile), lostPrefix) {
		return "lost mode was not active", nil
	}
	if err := os.Remove(nologinFile); err != nil {
		return "", err
	}
	if _, err := a.releasePasswords(); err != nil {
		a.event("releasing local passwords: %v", err)
	}
	a.event("lost mode ended")
	return "logins allowed again; set a new disk passphrase with the recovery key", nil
}

func (a *Agent) wipe() (string, error) {
	vols := luksVolumes()
	if len(vols) == 0 {
		return "", errors.New("no LUKS volumes: the data cannot be erased reliably, use lost mode instead")
	}
	var report []string
	var errs []error
	for _, v := range vols {
		if out, err := sh("cryptsetup", "luksErase", "--batch-mode", v.Path); err != nil {
			errs = append(errs, fmt.Errorf("%s: %s", v.Path, lastLines(out, 1)))
			continue
		}
		report = append(report, v.Path+": key slots erased, data unrecoverable")
	}
	a.event("device wiped")
	// power off after the result was reported with the next check in
	_, _ = sh("shutdown", "-h", "+2", "LiMDM: device wiped by IT")
	a.syncNow = true
	return strings.Join(report, "\n"), errors.Join(errs...)
}
