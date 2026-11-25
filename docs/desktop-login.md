# Desktop login

Centrally managed users sign in to their Linux device with their identity provider account
(Google Workspace, Entra ID, Okta, any OIDC provider with the device authorization grant).
LiMDM supports two modes:

| Mode | `local_password` | Day to day | Offline |
|---|---|---|---|
| **Local password after SSO** (recommended) | `true` | local password, SSO again every `reverify_hours` | yes, within `reverify_hours` |
| **SSO only** | `false` | SSO at every login and every screen unlock | no |

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
    "allowed_domain": "example.com", "local_password": true, "reverify_hours": 168}
   ```

   `allowed_domain` restricts sign in to the Google `hd` claim or the email domain.
   `reverify_hours` (1 to 2160) is required with `local_password`.
3. Optional offline lock in `com.limdm.agent`: `"offline_lock_hours": 72`.
4. On the device page, list the **Desktop users**, one per line: `username email [admin]`.
   The agent creates the accounts (home directory, `/bin/bash`), adds `admin` users to
   `sudo` or `wheel` and removes the right again when the flag is gone.

The agent inserts `pam_exec` with `limdm-agent pam-auth` before `pam_unix`: via
`pam-auth-update` on Debian and Ubuntu, via its own `authselect` profile on Fedora. This
covers every login manager and service that uses the common PAM stack: GDM, SDDM, LightDM,
text console, SSH and the lock screen. Removing the declaration removes the PAM integration.

## Local password after SSO

### First login

1. The login screen asks for the password. The user types the password they want to use on
   this device (at least 14 characters, must not contain the user name).
2. The screen shows a URL and a code. The user opens the URL on a phone or another device,
   signs in at the identity provider (with MFA, if configured) and confirms the code.
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
local password is currently locked. Every desktop login (success and failure, with reason)
is reported to the server and appears in the audit log.

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
* The client secret of the device flow client is stored unencrypted on the server and on the
  device (root only). Device flow clients are public clients at most providers; treat the
  secret as not confidential.
* Unmanaged local accounts keep their normal password login.

## Login managers

GDM, SDDM and LightDM show the PAM messages (URL and code) as text; how they look depends
on the theme. QR codes are not shown. A plain text console and SSH show the same text.
