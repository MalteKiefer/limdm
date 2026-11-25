# Disk encryption recovery keys

LiMDM checks that the system disk is encrypted with LUKS (`disk.encryption`) and stores a
recovery key for every LUKS volume on the server, so IT can restore access when a user
forgets the passphrase. Encryption itself happens at installation; LiMDM cannot encrypt an
existing disk.

## Enable

Library item `com.limdm.diskencryption`, assigned in a blueprint:

```json
{"escrow": true, "rotate_after_view": true}
```

The compliance check `disk.recovery` fails while a LUKS volume has no escrowed key.

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

* The server seals each key with AES-256-GCM. The key is derived from
  `LIMDM_SESSION_KEY`; device ID and volume UUID are bound as additional data, so a sealed
  key cannot be moved to another device.
* Admins and helpdesk see the volumes on the device page (Hardware tab) and reveal a key
  with **Show key** (a POST request with CSRF protection, the page is not cached). Auditors
  cannot reveal keys.
* Every escrow and every view is written to the audit log with the person who viewed it.

Enter the recovery key at the boot prompt instead of the passphrase.

## Rotation after view

With `rotate_after_view` a key is replaced after someone viewed it:

1. The server marks the key and sends the current key with the next check in.
2. The agent adds a new generated key using the current one, verifies it and escrows it.
3. Only after the server confirmed the new key, the agent removes the old key slot.

The device page shows "rotation pending" until then. If the device is offline, the viewed
key keeps working until the device checks in again.

## Lost or stolen devices

Two admin actions on the device page (Actions menu), each confirmed by typing the host name
and written to the audit log. They run when the device checks in the next time; a device
that stays offline is covered by `offline_lock_hours` ([desktop-login.md](desktop-login.md#offline-lock)).

**Lost mode** blocks every login (`/etc/nologin` with your message, local passwords locked),
ends running sessions and, for every LUKS volume with an escrowed recovery key, removes every
other key slot. The server adds the recovery keys to the command only at delivery; they are
never stored in the command. After the next power off only IT can open the disk, with the
recovery key from the console. Volumes without an escrowed key keep their slots; the result
on the device page says so.

**End lost mode** lifts the login block. The user's passphrase was removed: unlock the disk
with the recovery key at boot and set a new passphrase, for example with
`cryptsetup luksAddKey` using the recovery key, then rotate the viewed recovery key.

**Wipe** erases the LUKS headers of all volumes (`cryptsetup luksErase`), which makes the data
unrecoverable, and powers the device off two minutes later, after reporting the result. Devices
without LUKS are refused, because there is no fast way to guarantee deletion; use lost mode.

## Limits

* Only volumes visible to `lsblk` as `crypto_LUKS` are handled.
* TPM or FIDO2 unlock (`systemd-cryptenroll`) is not managed; such slots are left alone,
  except in lost mode, which removes every slot but the recovery key.
* Changing `LIMDM_SESSION_KEY` makes stored keys unreadable. Escrow again after a change.
