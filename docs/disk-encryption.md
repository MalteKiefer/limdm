# Disk encryption recovery keys

LiMDM checks that the system disk is encrypted with LUKS (`disk.encryption`) and stores a
recovery key for every LUKS volume on the server, so IT can restore access when a user
forgets the passphrase. Encryption itself happens at installation; LiMDM cannot encrypt an
existing disk.

## Enable

Library item `com.limdm.diskencryption`, assigned in a blueprint:

```json
{"escrow": true, "rotate_after_view": true, "require_all": true, "exclude": ["/boot"]}
```

The compliance check `disk.recovery` fails while a LUKS volume has no escrowed key. With
`require_all` the check `disk.encryption` needs every local volume on LUKS except the mount
points in `exclude` (an entry covers everything below it); without it only `/` counts. Every
field with its limits: [declarations.md](declarations.md#comlimdmdiskencryption).

## How the key is created

Adding a key slot needs an existing passphrase, which only the user knows. Therefore:

1. The desktop helper `limdm-desktop` asks the user at login, and then once a day while a
   key is missing, with a dialog showing the company name and logo:
   "*Company* needs a recovery key for the encrypted disk ...". The user can postpone.
   The menu entry "Disk recovery key" starts it at any time.
2. The user enters the current disk passphrase. The helper sends it over
   `/run/limdm/agent.sock` to the agent. The agent accepts it only from a user with an
   active local session and allows five wrong passphrases per 15 minutes per user.
3. The agent generates a recovery key in the systemd format (64 characters in eight groups,
   about 256 bits), adds it with `cryptsetup luksAddKey`, verifies it with
   `cryptsetup open --test-passphrase` and sends it with the next check in. The passphrase
   is used once and never stored or sent; it only exists briefly in a private tmpfs file.
4. The user's passphrase stays unchanged.

Administrators can do the same in a terminal: `sudo limdm-agent recovery-key`.

If no desktop helper runs (no graphical session, no zenity or kdialog), the agent shows a
desktop notification once a day pointing to the menu entry.

## Storage and access

* The server seals each key with AES-256-GCM under a key derived from `LIMDM_SESSION_KEY`;
  device ID and volume UUID are bound as additional data, so a sealed key cannot be moved to
  another device or volume. A session key rotation seals every key again with the new key
  ([keys.md](keys.md#session-key)).
* Admins and helpdesk accounts (within their device scope) see the volumes on the device page
  (**Hardware**, **Recovery keys**) and reveal a key with **Show key** (a POST request with
  CSRF protection, the answer is not cached). Auditors cannot reveal keys.
* Every escrow (`recovery.escrow`) and every view (`recovery.view`, with the viewer, the
  reason and the approval) is written to the audit log.

Enter the recovery key at the boot prompt instead of the passphrase.

### Four eyes approval for key views

With **Settings**, **Security**, **Four eyes approval** on, the option "Also for recovery key
views" makes every view wait for a second administrator
([security.md](security.md#four-eyes-approval)):

1. **Show key** opens **Request access to the recovery key**. The viewer enters a reason or
   ticket reference (required, one line up to 500 characters) and sends **Request approval**.
2. The request appears under **Approvals** and is announced as `approval.request`. Another
   administrator approves or rejects it; the requester can never decide their own request.
   Requests nobody decides expire after 24 hours.
3. After approval the requester opens the key with **Show key** again, once, within one hour.
   The audit entry names the approval number, the approver and the reason.

While a request is pending, **Show key** shows "Waiting for approval". With the option off,
admins and helpdesk see the key directly.

### Notification on every view

Every view raises the notification event `recovery.view` ("Recovery key viewed", severity
warning) with the viewer, the volume, the reason (or "none given") and a link to the device.
Subscribe a channel to it under **Settings**, **Notifications**
([notifications.md](notifications.md#channels)) to learn about each view at once.

## Rotation after view

With `rotate_after_view` a key is replaced after someone viewed it:

1. The server marks the key and sends the current key with the next check in.
2. The agent adds a new generated key using the current one, verifies it and escrows it.
3. Only after the server confirmed the new key, the agent removes the old key slot.

The device page shows "rotation pending" until then. If the device is offline, the viewed
key keeps working until the device checks in again.

## TPM unlock

With a `tpm2` entry the agent binds LUKS volumes to the TPM 2.0, so the disk opens at boot
without a passphrase as long as the measured boot state is unchanged:

```json
{"escrow": true, "rotate_after_view": true, "tpm2": {"pcrs": [7], "pin": false, "require": true}}
```

* `pcrs`: the PCRs the key is sealed to, default 7 (Secure Boot state and its certificates).
  Add 0, 2 or 4 for firmware and boot loader measurements; every firmware or boot loader
  update then needs the recovery key once and a new binding.
* `pin`: the TPM also needs a PIN at boot.
* `require`: the compliance check `disk.tpm` fails while a volume is not bound. Without it the
  check only reports the state.

How it works:

1. Binding needs a current key of the volume. The agent holds one only right after a recovery
   key was created or rotated, so a volume is bound when the server confirmed its new
   recovery key: `systemd-cryptenroll --unlock-key-file=<recovery key> --tpm2-device=auto
   --tpm2-pcrs=7 --wipe-slot=tpm2`. The key file lives in a private tmpfs directory and is
   removed right after.
2. The recovery key slot stays; only an earlier TPM2 slot is replaced, so a changed PCR list
   applies with the next binding.
3. Volumes escrowed before the `tpm2` entry are bound with their next key rotation: view the
   key in the console with `rotate_after_view`, or run `sudo limdm-agent recovery-key --all`.
4. With `pin` the agent never binds by itself, because only the user may know the PIN.
   `sudo limdm-agent recovery-key --all` asks for the passphrase, adds a new recovery key,
   asks for a PIN (at least 6 characters, twice) and binds the volume. The PIN goes to
   `systemd-cryptenroll` in its environment, never on the command line.
5. Where dracut builds the initrd (Fedora, SUSE, Arch with dracut) the agent adds
   `/etc/dracut.conf.d/60-limdm-tpm2.conf` with the `tpm2-tss` module and runs
   `dracut -f --regenerate-all` once. Debian and Ubuntu with initramfs-tools cannot unseal a
   TPM2 key at boot; there the binding exists but the passphrase prompt stays until the
   initrd uses dracut or systemd.

Requirements: a TPM 2.0 (`/sys/class/tpm/tpm0`), LUKS2 and systemd 252 or newer
(`--unlock-key-file`). The device page shows the TPM version and the bound volumes in the
Hardware tab; the inventory reports them as `tpm`.

Lost mode removes every key slot except the recovery key, the TPM slot included; the agent
binds again only with the next escrowed recovery key.

## Lost or stolen devices

Two admin actions on the device page (Actions menu), each confirmed by typing the host name
and written to the audit log. With four eyes approval on, both wait for a second
administrator under **Approvals** first ([security.md](security.md#four-eyes-approval)).
Sending either one raises the notification event `command.wipe_lost`. They run when the
device checks in the next time; a device that stays offline is covered by
`offline_lock_hours` ([desktop-login.md](desktop-login.md#offline-lock)).

**Lost mode** blocks every login (`/etc/nologin` with your message, local passwords locked),
ends running sessions and, for every LUKS volume with an escrowed recovery key, removes every
other key slot. The server adds the recovery keys to the command only at delivery; they are
never stored in the command. After the next power off only IT can open the disk, with the
recovery key from the console. Volumes without an escrowed key keep their slots; the result
on the device page says so.

**End lost mode** lifts the login block; it needs no approval. The user's passphrase was removed: unlock the disk
with the recovery key at boot and set a new passphrase, for example with
`cryptsetup luksAddKey` using the recovery key, then rotate the viewed recovery key.

**Wipe** erases the LUKS headers of all volumes (`cryptsetup luksErase`), which makes the data
unrecoverable, and restarts the device two minutes later, after reporting the result. The
restart is forced: sleep is blocked until then, a device that slept through the two minutes
restarts as soon as it wakes up, inhibitors are ignored and, if systemd refuses, the agent
reboots through the kernel (`/proc/sysrq-trigger`). After the restart the disk cannot be
unlocked any more. Devices
without LUKS are refused, because there is no fast way to guarantee deletion; use lost mode.

## Limits

* Only volumes visible to `lsblk` as `crypto_LUKS` are handled.
* FIDO2 unlock is not managed; such slots are left alone, except in lost mode, which
  removes every slot but the recovery key.
* The agent's own mTLS key is kept in the TPM independent of LUKS binding
  ([agent.md](agent.md#tpm-bound-device-key)).
* Replacing `LIMDM_SESSION_KEY` outright makes stored keys unreadable. Rotate it as
  described in [keys.md](keys.md#session-key) instead: the old key stays listed until every
  recovery key is sealed again.
