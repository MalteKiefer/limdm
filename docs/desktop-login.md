# Desktop login

Centrally managed users sign in to their Linux device with their identity provider account
(Google Workspace, Entra ID, Okta, any OIDC provider with the device authorization grant).
LiMDM supports two modes:

| Mode | Login screen | Confirmation | Offline |
|---|---|---|---|
| **session** (default, like Apple Platform SSO and Iru Passport) | local password; SSO with MFA only at the first login and after a lock | every `reverify_hours` (default 720, 30 days) in the session: the desktop app asks, the user confirms in the browser | always works; nothing locks while offline |
| **login** (strict) | SSO every `reverify_hours`, with `local_password` the local password in between | at the login screen | `offline_grace_hours` on top (default 72) |

In **session** mode:

* The first login binds the account: SSO with MFA, and the password typed there becomes the
  local password.
* Afterwards the local password works on every login and lock screen, also offline.
* When a confirmation is due, the tray shows **Confirm Company Account…** and a
  notification once a day. A click opens the identity provider's page and shows a code;
  the confirmation happens in the browser with MFA, the session goes on.
* If nobody confirms within `grace_hours` (default 168, 7 days) after it fell due, and the
  device is online, the local password locks. The next login then needs SSO at the login
  screen, which unlocks it again. A device that is offline is never locked for this, so a
  long flight or a holiday without network changes nothing.
* Accounts suspended or deleted in the directory (SCIM, Google Workspace sync) are locked
  at the next poll, within about a minute when online, and their sessions end; this is the
  counterpart of revoking tokens in Entra ID.

This is not a password synchronisation with the identity provider (Google offers no
interface to verify a password, except Secure LDAP). The identity provider decides who may
use the device; the local password is a device password the user sets during an SSO
confirmation.

## Setup

1. Create an OAuth client of type **TVs and Limited Input devices** at the provider
   (Google Cloud console: APIs and Services, Credentials). It must support the device
   authorization grant (RFC 8628).
2. Create a library item `com.limdm.login` and assign it in a blueprint:

   ```json
   {"issuer": "https://accounts.google.com", "client_id": "...", "client_secret": "...",
    "allowed_domain": "example.com", "mode": "session", "reverify_hours": 720, "grace_hours": 168}
   ```

   `allowed_domain` restricts sign in to the Google `hd` claim or the email domain.
   Session mode: `reverify_hours` 1 to 8760 (default 720), `grace_hours` 1 to 2160
   (default 168). Login mode (`"mode": "login"`): `reverify_hours` 1 to 2160 with
   `local_password`; `offline_grace_hours` (default 72, at most 720) lets a due confirmation
   wait while the device cannot reach the LiMDM server.
   Without `mode` the item runs in session mode, except items written before 0.11:
   those carry `local_password` and keep login mode.

**Switching SSO off** (servers, kiosks): assign a login library item with
`{"enabled": false}` to that blueprint. Declarations apply from the parent blueprint to the
child, so it overrides SSO inherited from above; the agent removes its PAM hook and local
logins work as before.

**Travel and holidays:** in session mode nothing locks while the device is offline, so an
18 hour flight or 14 days without network need no setting; after the trip the tray asks for
the confirmation. Only the agent's own offline lock (`offline_lock_hours` in the agent
item) can lock a device that is away; keep it at 0 (off) or longer than the longest trip.
In login mode, set `offline_grace_hours` longer than the trip (for example 360 for two
weeks), or give travellers a **travel** tag whose blueprint condition assigns a login item
with longer values.
3. Optional offline lock in `com.limdm.agent`: `"offline_lock_hours": 72`.
4. On the device page, list the **Desktop users**, one per line: `username email [admin]`.
   The agent creates the accounts (home directory, `/bin/bash`), adds `admin` users to
   `sudo` or `wheel` and removes the right again when the flag is gone.

The agent inserts `pam_exec` with `limdm-agent pam-auth` before `pam_unix` in the shared
auth stack:

| Family | How |
|---|---|
| Debian, Ubuntu | `pam-auth-update` with the profile `/usr/share/pam-configs/limdm` |
| Fedora, RHEL | its own `authselect` profile `custom/limdm`, cloned from the current one; the previous profile is restored on removal |
| SUSE | `/etc/pam.d/common-auth` (the `common-auth-pc` file of pam-config) |
| Arch | `/etc/pam.d/system-auth` |
| Alpine | `/etc/pam.d/base-auth`, needs linux-pam |

On SUSE, Arch and Alpine the original file is kept in `/var/lib/limdm/pam-<name>.orig`. If
another tool removes the line, the agent adds it again. Removing the declaration removes the PAM integration.

The device flow runs only for services at the device: display managers (GDM, SDDM,
LightDM, LXDM, greetd, cosmic-greeter and others), screen lockers (GNOME, KDE, Xfce,
Cinnamon, MATE, swaylock, hyprlock, i3lock and others), the text console (`login`) and
polkit. `sshd` and every other remote service never start a device flow: for them
`pam_unix` decides with the local password alone. A managed user whose local password is
locked (confirmation due, SSO only mode, offline lock) therefore cannot sign in over SSH,
and a network client cannot find out which accounts are managed.

`su`, `su -l`, `sudo` and `sudo -i` never start a device flow either. Any local or SSH user
could otherwise run `su alice`, show alice's code and ask her to confirm it (device code
phishing); with the local password option the typed password would become hers. For these
services `pam_unix` decides; a managed user with a locked local password confirms at the
login screen or the screen locker first.

For the listed services the agent also refuses the device flow when
`PAM_RHOST` is set (any value, `localhost` included), when `PAM_TTY` is a pseudo terminal
(`/dev/pts/N`), or when the calling process runs in a remote logind session (`REMOTE=1` in
`/run/systemd/sessions/<id>`) or below the SSH service. polkit may authenticate as
another, admin user, so it runs the flow only inside a local logind session with a seat;
a polkit helper outside any session falls back to `pam_unix`. **On GNOME and KDE Plasma this
is always the case** (the shell and its polkit helper run under `user@.service`, newer polkit
starts the helper by socket activation), so polkit prompts there use the local password and
SSO only accounts cannot answer them. Login services and screen
lockers may run outside a session: display managers and `login` authenticate before the
session exists, and a locker only unlocks its own user.

## Local password after SSO

### First login

1. The login screen asks for the password. The user types the password they want to use on
   this device (at least 14 characters, must not contain the user name).
2. The screen shows a URL and a code. The user opens the URL on a phone or another device,
   signs in at the identity provider (with MFA, if configured) and confirms the code. The
   login waits up to five minutes.
3. The agent verifies the ID token: signature, issuer, audience, verified email, the email
   mapped to this user and the allowed domain.
4. The typed password becomes the local password, the confirmation time is stored, and the
   user is signed in.

### Day to day

Within `reverify_hours` after the last confirmation, login and screen unlock use the local
password only (`pam_unix`). This works offline. The user may change it with `passwd`.

### Reconfirmation

When `reverify_hours` have passed, the agent locks the local password. At the next login or
screen unlock the hook asks for SSO again, exactly like the first login. The password typed
at that login becomes the new local password, so a forgotten local password is reset by
simply typing a new one and confirming with SSO.

An identity provider account that was disabled or lost its access cannot confirm, so the
user stays locked out after `reverify_hours` at the latest, even when the device is offline.

### Without network

* Within `reverify_hours`: login with the local password works.
* After `reverify_hours`: login needs SSO, which needs internet access to the identity
  provider (not to the LiMDM server). The user cannot sign in until the device is online.

The login screen only uses network connections available before login. Wi-Fi profiles
stored per user connect only after login; make the company Wi-Fi a system connection:

```sh
nmcli connection modify "<name>" connection.permissions ""
```

## SSO only

With `"local_password": false` every login and every screen unlock runs the device flow.
The agent keeps the local passwords of managed users locked, so only SSO works. There is no
offline login. Use this mode for shared or kiosk devices with permanent network access.

## Offline lock

`offline_lock_hours` in `com.limdm.agent` locks the whole device when it could not reach the
LiMDM server for longer than that:

* The agent writes `/etc/nologin` (`pam_nologin` refuses every login except root),
  locks the local passwords of all managed users and locks running sessions.
* The PAM hook also refuses managed users while the lock is active, and checks the time of
  the last server contact itself, so a device that was switched off for a long time is
  locked even before the agent ran.
* The lock is lifted automatically by the next successful check in. The device needs a
  network connection available at the login screen (see above).
* A manual lock from the console keeps its own message and is only lifted by `unlock`.

Check in happens every `checkin_seconds`, so `offline_lock_hours` should be much larger than
the check in interval, for example 72 hours for laptops that travel.

## Users removed or deactivated

* Removed from the device's user list: the agent removes admin rights and locks the account
  (`usermod -L -e 1`) at the next check in. The home directory is kept. Adding the user
  again unlocks it.
* Deactivated in the directory (SCIM `active: false`, Google suspended user): the server
  drops the user from the list of every device at its next check in, with the same effect.

Together with `reverify_hours` and `offline_lock_hours` this bounds how long a removed
person keeps access: immediately for online devices, at the latest after the shorter of
both periods for offline ones.

## What the console shows

The device page lists for every managed account the last SSO confirmation and whether the
local password is currently locked. Every SSO login (success and failure, with reason) is
written to `/var/lib/limdm/auth-events.log`, reported with the next check in and shown under
**Device events** on the device's **Commands** tab (kept 365 days). A user deactivated in
the directory also raises the notification event `directory.user_disabled`.

## Files on the device

| File | Content |
|---|---|
| `/etc/limdm/users.json` | username to email mapping of managed users (0600) |
| `/etc/limdm/login.json` | login configuration incl. client secret and offline limit (0600) |
| `/var/lib/limdm/sso-verified.json` | last SSO confirmation per user (0600) |
| `/var/lib/limdm/auth-events.log` | login results until the next check in (0600) |

## Security notes

* Users must only confirm codes they see on their own device's login screen. The device
  authorization grant is open to phishing when someone sends a code to a victim; MFA does
  not prevent that.
* The local password never leaves the device. It is stored by `chpasswd` with the system's
  password hashing (yescrypt on current distributions).
* The client secret of the device flow client is stored encrypted on the server: the console
  seals `client_secret` of a `com.limdm.login` item with AES-256-GCM under a key derived from
  `LIMDM_SESSION_KEY` (the editor then shows `sealed:v1:…`; type a new secret in clear to
  replace it). Items saved by older versions are sealed at the first start, and after a
  session key rotation the secrets are sealed again with the new key
  ([keys.md](keys.md#session-key)). The audit log and the version history record the
  sealed form only. The server opens the secret when it builds a device's
  declarations and sends it over mTLS.
* On the device the secret stays in clear (`/etc/limdm/login.json` and the agent state, root
  only, 0600): the agent sends it to the provider in the device authorization grant and has
  no key the server could seal it for. Device flow clients are public clients at most
  providers; treat the secret as not confidential and restrict the client to the device
  flow.
* Unmanaged local accounts keep their normal password login.

## Login managers

GDM, SDDM and LightDM show the PAM messages (URL and code) as text; how they look depends
on the theme. QR codes are not shown. A plain text console shows the same text. SSH shows
nothing of it, because remote services never run the device flow.
