# Configuration

Bootstrap values (database, listeners, keys) come from the environment. Everything else is
configured in the console and stored in the database; values saved in the console override
the environment.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `LIMDM_DATABASE_URL` | required | PostgreSQL URL. Remote hosts need `sslmode=verify-full`. |
| `LIMDM_SESSION_KEY` | required | At least 32 bytes as hex (`openssl rand -hex 32`). Signs sessions and derives the keys for stored secrets, recovery keys and webhook signatures. Changing it invalidates sessions and makes stored secrets unreadable. |
| `LIMDM_PUBLIC_URL` | required | Console URL as users see it, for example `https://mdm.example.com`. |
| `LIMDM_AGENT_URL` | required | Agent API URL, `https://`. Its host goes into the server certificate agents verify. |
| `LIMDM_AGENT_LISTEN` | `:8444` | Listener of the agent API (mTLS terminates here). |
| `LIMDM_AGENT_HOSTS` | | Extra names or IPs for the agent certificate, comma separated. |
| `LIMDM_LISTEN` | `127.0.0.1:8080`, `:8443` with a certificate | Console listener. Without a certificate only loopback is allowed. |
| `LIMDM_TLS_CERT`, `LIMDM_TLS_KEY` | | Console certificate when no reverse proxy is used. |
| `LIMDM_CA_DIR` | `/var/lib/limdm-server/ca` | Device CA (key file 0600). Back it up. |
| `LIMDM_LOCAL_LOGIN` | `false` | Allow local accounts (password and TOTP). |
| `LIMDM_OIDC_ISSUER`, `LIMDM_OIDC_CLIENT_ID`, `LIMDM_OIDC_CLIENT_SECRET` | | Console single sign on. Optional; also configurable in the console. |
| `LIMDM_OIDC_ALLOWED_DOMAIN` | | Only accept this Google `hd` claim or email domain. |
| `LIMDM_ADMINS`, `LIMDM_AUDITORS` | | Comma separated emails seeded as console users at start. |
| `LIMDM_STALE_HOURS` | `24` | Hours without check in until a device counts as stale. |
| `LIMDM_RELEASE_DIR` | `/var/lib/limdm-server/agent-releases` | Cache of verified agent packages for updates ([agent.md](agent.md#updates)). |
| `LIMDM_RELEASE_REPO` | `MalteKiefer/limdm` | GitHub repository for agent updates and `/install.sh`. |
| `LIMDM_GEOIP_URL` | `https://ipwho.is/` | Location lookup for device public addresses, the IP is appended. Used only when **Settings, Security, Privacy** turns geolocation on (default off); `off` disables it for good ([security.md](security.md#privacy)). |
| `LIMDM_SYSLOG` | | Forward audit entries and device events as RFC 5424 syslog, `udp://host:514` or `tcp://host:514` ([security.md](security.md#audit-log)). |

The server refuses to start when OIDC and local login are both off, when OIDC is set without
an administrator, or when the console would listen publicly without a certificate.

## Console settings

**Settings** (admins edit, auditors read) has the tabs General, Security, SSO, Notifications
and Branding; each form saves only its own fields:

* **Single sign on (OIDC).** Issuer, client ID, client secret (stored AES-256-GCM encrypted)
  and allowed domain. Changes are checked against the provider's discovery document before
  they take effect, no restart needed. Redirect URI: `<LIMDM_PUBLIC_URL>/auth/callback`.
* **Local accounts.** Can only be disabled while an OIDC administrator exists and you are
  signed in with OIDC, so nobody locks everyone out.
* **Multi factor authentication (SSO tab).** With **Require multi factor authentication**
  an OIDC sign in is refused unless the id token's `amr` claim names `mfa` (or `mca`), or two
  methods one of which is a second factor (`otp`, `hwk`, `swk`, `sms`, `tel`, `sc`, `pop`,
  `fpt`, `face`, `iris`, `retina`, `vbm`). With **Accepted acr values** set, the `acr` claim
  must be one of them instead, and the sign in request asks for them (`acr_values`).
  Refused sign ins are audited as `login.denied`. Google sends neither claim: enforce
  two step verification in the Workspace admin console, or use acr values your provider sets.
* **Console roles from groups (SSO tab).** One mapping per line, `group; role; tags`, for
  example `support; helpdesk; berlin,munich`. Groups are directory groups (Google
  Workspace sync, SCIM) by name, and the OIDC `groups` claim when the provider sends one.
  A person without an explicit console account whose groups map to a role gets an account
  at sign in (marked *from directory group*); its role is derived again on every request,
  so leaving the group ends access after the next directory sync. The strongest mapped role
  wins; tags limit helpdesk and auditor roles (see scopes below). Accounts created or
  edited in **Users** are explicit and ignore the mapping.
* **Four eyes approval (Security tab).** See [security.md](security.md#four-eyes-approval).
* **Audit log retention (Security tab).** 0 keeps everything (default); otherwise 365 to
  36500 days ([security.md](security.md#audit-log)).
* **Stale threshold** (General).
* **Notifications.** Notification channels ([notifications.md](notifications.md)) and the
  compliance webhook ([compliance.md](compliance.md#webhook)) on one tab.
* **Remote shell** (tab Security): on or off, helpdesk allowed, root allowed, maximum
  duration and idle timeout ([remote-shell.md](remote-shell.md)).
* **Branding.** Company name (up to 80 characters) and a PNG logo (16 to 1024 pixels, up to
  256 KiB, square works best). Shown in the console, on the sign in page and in the desktop
  helper's dialogs and notifications on devices. Only PNG is accepted because an SVG served
  from the console's origin could carry script.

Every change is written to the audit log.

## Google Workspace as identity provider

Console sign in:

1. Google Cloud console, APIs and Services, Credentials: create an OAuth client of type
   **Web application** with the redirect URI `https://mdm.example.com/auth/callback`.
2. Enter issuer `https://accounts.google.com`, client ID, secret and your Workspace domain
   in **Settings**.
3. Add the people who may use the console in **Users**.

Desktop login uses a second OAuth client of type **TVs and Limited Input devices** (device
authorization grant). See [desktop-login.md](desktop-login.md).

Other providers (Entra ID, Okta, authentik, Keycloak) work the same way with their issuer URL.

## Console users and roles

| Role | May |
|---|---|
| `admin` | everything |
| `helpdesk` | see devices; sync, install updates, reboot, shut down, lock and unlock, send a message; reset the password of and lock local accounts on a device; reveal disk recovery keys. Not: scripts, lost mode, wipe, retire, software, creating or deleting accounts, configuration |
| `auditor` | read everything, change nothing |

Users are OIDC identities (email) or local accounts (`local:<name>`, password and TOTP).
Rules enforced by the server:

* At least one active administrator always remains (two while four eyes approval is on).
* Nobody can demote, disable or reset their own account. The own row in **Users** is read
  only; personal settings live in the **Profile**.

**Scopes.** Helpdesk and auditor accounts can be limited to device tags and directory
groups (comma separated in **Users**; a device is in scope when it carries one of the tags
or its primary user is in one of the groups). Empty means every device; admins are never
limited. The server enforces the scope on the device list, overview, compliance page, device
page, commands (single and bulk), recovery keys, CSV exports (also packages and compliance
history), the compliance history page and the audit log with its CSV and JSON Lines exports
(entries about devices in scope); a device outside the scope is answered with 404. Pages
with fleet wide data that are not filtered (Directory, Agents, Software, Network
certificates, version history) are refused to scoped accounts. API tokens can carry scope
tags too ([admin-api.md](admin-api.md#tokens)); scoped tokens get no metrics.

## Profile

Every user opens the profile by clicking their name in the sidebar:

* **Language:** English or German, stored in the browser. Without a choice the browser's
  `Accept-Language` decides.
* **Local accounts only:**
  * change the password (current password required, 12 to 256 characters),
  * move TOTP to a new authenticator app: a QR code is shown, the new secret takes effect
    only after a code from the new app was entered,
  * recovery codes: ten one time codes, usable instead of a TOTP code at sign in. They are
    shown once and stored as SHA-256 hashes; the profile shows how many are left.
    Generating new codes invalidates the old ones.

Password checks in the profile count towards the same lockout as the sign in (5 failures,
15 minutes). OIDC accounts are managed by the identity provider.

## Directory

**Directory** connects people and groups:

* **SCIM 2.0** at `<LIMDM_PUBLIC_URL>/scim/v2` (filters: `attribute eq "value"` only, others are answered with 400 `invalidFilter`; no ETags) with a bearer token created on the page
  (Okta, Microsoft Entra ID, authentik, JumpCloud).
* **Google Workspace:** a service account with domain wide delegation for the scopes
  `admin.directory.user.readonly`, `admin.directory.group.readonly` and
  `admin.directory.group.member.readonly`, plus an admin email to impersonate. Synced hourly
  and on demand.

How groups select blueprints and what deactivation does: [concepts.md](concepts.md#directory).

## Password policy

Settings, Security sets the rules for passwords chosen in the console: initial and reset
passwords of local accounts on devices, and the passwords of local console accounts. The
minimum length is 12 to 128 characters (default 12); uppercase, lowercase, digit and special
character can be required, and the user name can be ruled out. Generated passwords (new local
console accounts, resets) are random and not affected. Passwords people set on their devices
follow the compliance check `accounts.pwquality`.
