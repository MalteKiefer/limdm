# Configuration

Bootstrap values (database, listeners, keys) come from the environment. Everything else is
configured in the console and stored in the database. The console settings start from the
environment (OIDC, allowed domain, local login, stale threshold); once saved in the console,
the saved values win.

## Environment variables

Read by `limdm-server serve` (`ConfigFromEnv`). The package reads them from
`/etc/limdm-server/server.env`, Docker Compose from `.env` ([below](#docker-compose)).

| Variable | Default | Meaning |
|---|---|---|
| `LIMDM_DATABASE_URL` | required | PostgreSQL URL. Remote hosts need `sslmode=verify-full`; only a unix socket or loopback may go without it. |
| `LIMDM_SESSION_KEY` | required | At least 32 bytes as hex (`openssl rand -hex 32`). Signs sessions and derives the keys for sealed values (stored secrets, recovery keys). During a rotation a comma separated list, the new key first: the first seals and signs, all of them open and verify; old values are sealed again in the background. Replacing it without a rotation invalidates sessions and makes stored secrets unreadable ([keys.md](keys.md#session-key)). |
| `LIMDM_PUBLIC_URL` | required | Console URL as users see it, `https://` only, for example `https://mdm.example.com`. |
| `LIMDM_AGENT_URL` | required | Agent API URL, `https://host:port`. Its host goes into the server certificate agents verify. |
| `LIMDM_AGENT_LISTEN` | `:8444` | Listener of the agent API (mTLS, TLS 1.3, terminates here). |
| `LIMDM_AGENT_HOSTS` | | Extra names or IPs for the agent certificate, comma separated ([installation.md](installation.md#moving-to-another-dns-name)). |
| `LIMDM_LISTEN` | `127.0.0.1:8080`, `:8443` with a certificate | Console listener. Without a certificate only loopback is allowed. |
| `LIMDM_TLS_CERT`, `LIMDM_TLS_KEY` | | Console certificate and key when no local reverse proxy terminates TLS. |
| `LIMDM_CA_DIR` | `/var/lib/limdm-server/ca` | Device CA, network CA, command key (key files 0600), `keys.json`, `audit-keys`, `audit-keyed-from`. Back it up ([keys.md](keys.md)). |
| `LIMDM_KEY_PROVIDER` | `file` | Where the private keys of the CAs and the command key live: `file` or `pkcs11` (HSM, needs a server built with `-tags pkcs11`). |
| `LIMDM_PKCS11_MODULE` | | Path of the PKCS#11 module, for `LIMDM_KEY_PROVIDER=pkcs11`. |
| `LIMDM_PKCS11_TOKEN` | | Token label. |
| `LIMDM_PKCS11_PIN` | | User PIN ([keys.md](keys.md#key-provider-and-hsm)). |
| `LIMDM_LOCAL_LOGIN` | `false` | `true` allows local accounts (password and TOTP). Starting value of the console setting. |
| `LIMDM_OIDC_ISSUER` | | Console single sign on, `https://` issuer. Optional; also configurable in the console. |
| `LIMDM_OIDC_CLIENT_ID` | | Required when `LIMDM_OIDC_ISSUER` is set. |
| `LIMDM_OIDC_CLIENT_SECRET` | | Client secret. |
| `LIMDM_OIDC_ALLOWED_DOMAIN` | | Only accept this Google `hd` claim or email domain. |
| `LIMDM_ADMINS` | | Comma separated emails seeded as console admins at start. Required when `LIMDM_OIDC_ISSUER` is set. |
| `LIMDM_AUDITORS` | | Comma separated emails seeded as console auditors at start. |
| `LIMDM_STALE_HOURS` | `24` | Hours without check in until a device counts as stale (positive integer). Starting value of the console setting. |
| `LIMDM_RELEASE_DIR` | `/var/lib/limdm-server/agent-releases` | Cache of verified agent packages for updates ([agent.md](agent.md#updates)). The packaged `server.env` sets `/var/lib/limdm-server/releases`. |
| `LIMDM_RELEASE_REPO` | `MalteKiefer/limdm` | GitHub repository for agent updates and `/install.sh`. |
| `LIMDM_GEOIP_URL` | `https://ipwho.is/` | Location lookup for device public addresses, the IP is appended. Used only when **Settings, Security, Privacy** turns geolocation on (default off); `off` disables it for good ([security.md](security.md#privacy)). |
| `LIMDM_TRUSTED_PROXIES` | | Load balancers or reverse proxies whose `X-Forwarded-For` names the client, comma separated addresses or networks (`10.0.0.5,10.0.1.0/24`). A proxy on loopback is always trusted. Without it, a proxy on another host makes every request seem to come from the proxy (rate limits, console network lists, audit) ([high-availability.md](high-availability.md#load-balancer)). |
| `LIMDM_DRAIN_SECONDS` | `5` | On SIGTERM, how long `/readyz` fails before connections close, so load balancers stop sending requests (0 to 300). |
| `LIMDM_SYSLOG` | | Forward audit entries and device events as RFC 5424 syslog, `udp://host:514` or `tcp://host:514` ([operations.md](operations.md#syslog)). |
| `LIMDM_MULTI_TENANT` | `false` | `true` shows the tenant pages and the tenant switcher to global administrators ([tenants.md](tenants.md)). Tenant isolation applies regardless. |

The server refuses to start when OIDC and local login are both off, when OIDC is set without
an administrator in `LIMDM_ADMINS`, when `LIMDM_PUBLIC_URL` or `LIMDM_AGENT_URL` is not
`https`, or when the console would listen on a public address without a certificate.

`limdm-server local-admin -env FILE` and `limdm-server keys -env FILE` read the same
variables from an env file ([operations.md](operations.md#command-line)).

### install.sh

`<LIMDM_PUBLIC_URL>/install.sh` installs and enrolls the agent on a device. It is generated
by the server with its agent URL and device CA fingerprint and reads:

| Variable | Default | Meaning |
|---|---|---|
| `LIMDM_TOKEN` | | Enrollment token, written to `/etc/limdm/enroll.conf`. Without it an existing `enroll.conf` (or an enrolled device) is used, so the same command serves mass deployment. |
| `LIMDM_ALLOW_SCRIPTS` | `false` | `true` allows remote scripts on this device (`allow_scripts`). |
| `LIMDM_ALLOW_REMOTE_SHELL` | `false` | `true` allows remote support shells on this device (`allow_remote_shell`, [remote-shell.md](remote-shell.md)). |

The keys of `enroll.conf`, the agent's files under `/etc/limdm` and `/var/lib/limdm` and the
agent command line: [agent.md](agent.md#mass-deployment-enrollconf), [agent.md](agent.md#files).

### Docker Compose

[`deploy/docker/.env.example`](../deploy/docker/.env.example) lists the values
[`compose.yaml`](../deploy/docker/compose.yaml) uses:

| Variable | Meaning |
|---|---|
| `LIMDM_DOMAIN` | DNS name of the server. Sets `LIMDM_PUBLIC_URL` (`https://<domain>`), `LIMDM_AGENT_URL` (`https://<domain>:8444`) and the Caddy site. |
| `LIMDM_VERSION` | Image tag of `ghcr.io/maltekiefer/limdm-server`, default `latest`. |
| `LIMDM_SESSION_KEY` | As above. |
| `POSTGRES_PASSWORD` | Password of the database role `limdm`, hex only (part of the database URL). |
| `LIMDM_LOCAL_LOGIN` | As above, default `true`. |
| `LIMDM_OIDC_ISSUER`, `LIMDM_OIDC_CLIENT_ID`, `LIMDM_OIDC_CLIENT_SECRET`, `LIMDM_OIDC_ALLOWED_DOMAIN`, `LIMDM_ADMINS`, `LIMDM_AUDITORS` | As above, optional. |

`compose.yaml` sets `LIMDM_DATABASE_URL`, `LIMDM_LISTEN` (`127.0.0.1:8080`, Caddy shares the
network namespace) and `LIMDM_AGENT_LISTEN` itself. Other variables of the table above
(for example `LIMDM_SYSLOG`) must be added to the `environment` of the `limdm` service.

## Console settings

**Settings** is open to admins (edit) and auditors (read). It has the tabs General,
Security, SSO, Notifications and Branding; each form saves only its own fields, changes take
effect at once on every instance and are written to the audit log (`settings.save`).
Accounts of a tenant see only the Notifications tab with their own channels
([tenants.md](tenants.md)).

### General

* **Access.** **Allow local accounts (password + TOTP)**. Local accounts can only be switched
  off while OIDC is configured, an OIDC administrator exists and you are signed in with
  OIDC, so nobody locks everyone out. **Device counts as stale after (hours)**: 1 to 2160.
  The public URL is shown read only.
* **Console access by network.** **Allowed networks** and **Blocked networks**: addresses
  or CIDR ranges, separated by spaces or lines. Empty allowed networks means every network;
  blocked networks are refused even when allowed. Loopback is always allowed, the agent API
  is not affected. Saving is refused when your own address would be locked out. Behind a
  proxy on another host set `LIMDM_TRUSTED_PROXIES`, otherwise the proxy's address is checked.

### Security

* **Password policy.** See [below](#password-policy).
* **Four eyes approval.** **Require a second administrator's approval** for wipe, lost mode,
  scripts and role changes of console users; optionally **Also for recovery key views** (the
  viewer gives a reason or ticket reference) and **Also for remote shell sessions** (the
  approved session must be opened within one hour). Needs at least two active
  administrators ([security.md](security.md#four-eyes-approval)).
* **Audit log retention.** **Keep audit entries (days)**: 0 keeps everything (default),
  otherwise 365 to 36500. Older entries are deleted once a day after the full chain
  verified; a signed checkpoint keeps the rest verifiable ([security.md](security.md#audit-log)).
* **Privacy.** Both off by default: **Look up the location of device public addresses**
  (sends them to `LIMDM_GEOIP_URL`) and **Agents may ask public DNS over HTTPS resolvers
  (Cloudflare, Google) when the system resolver fails** ([security.md](security.md#privacy)).
* **Remote shell.** **Allow remote shells (admins)**, **The helpdesk role may start
  sessions**, **Sessions may run as root**, **Maximum duration (minutes)** (5 to 480,
  empty 60) and **Idle timeout (minutes)** (1 to 120, empty 15). A device also needs
  `allow_remote_shell` at enrollment ([remote-shell.md](remote-shell.md)).
* **Keys.** Only for global administrators without a scope. Lists the device CA, network CA,
  command key, session key and webhook signing secret with the active and retiring key,
  rotation progress and where each is stored, and starts and finishes rotations
  (**Rotate**, **Finish**, optional **force**). The session key is rotated with
  `limdm-server keys rotate session`. Each step is audited and takes effect after every
  instance restarted ([keys.md](keys.md)).

### SSO

* **Single sign on (OIDC).** Issuer, client ID, client secret (stored encrypted, **Remove the
  stored secret** clears it) and allowed domain (Google `hd` claim or email domain). Changes
  are checked against the provider's discovery document before they take effect, no
  restart needed. Redirect URI: `<LIMDM_PUBLIC_URL>/auth/callback`.
* **Require multi factor authentication (amr claim of the id token).** An OIDC sign in is
  refused unless the `amr` claim names `mfa` (or `mca`), or two methods one of which is a
  second factor (`otp`, `hwk`, `swk`, `sms`, `tel`, `sc`, `pop`, `fpt`, `face`, `iris`,
  `retina`, `vbm`). With **Accepted acr values** (up to 10, separated by spaces) the `acr`
  claim must be one of them instead, and the sign in request asks for them (`acr_values`).
  Refused sign ins are audited as `login.denied`. Google sends neither claim: enforce two
  step verification in the Workspace admin console, or use acr values your provider sets.
* **Console roles from groups.** One mapping per line, `group; role; tags`, for example
  `support; helpdesk; berlin,munich`. See [role groups](#role-groups). At most 100 lines.

### Notifications

* **Notification channels.** Slack, Discord, email (SMTP) or a signed webhook, each
  subscribed to chosen events (none selected: all events); **Send test**, **Switch off**,
  **Delete** ([notifications.md](notifications.md)).
* **Compliance webhook.** One `https` URL that receives signed JSON when a device becomes
  non compliant, independent of the channels. Admins see the **Signing key**
  (`X-LiMDM-Signature: sha256=HMAC-SHA256(key, body)`), also used by signed webhook
  channels; rotate it in **Settings, Security, Keys** ([compliance.md](compliance.md#webhook),
  [keys.md](keys.md#webhook-signing-secret)).

### Branding

Company name (up to 80 characters, one line) and a PNG logo (16 to 1024 pixels per side, up
to 256 KiB, square works best; **Remove logo**). Shown in the console, on the sign in page and
in the desktop helper's dialogs and notifications on devices. Only PNG is accepted because an
SVG served from the console's origin could carry script. With multi tenancy each tenant can
have its own name, logo and accent color, this one is the fallback ([tenants.md](tenants.md#branding)).

## Google Workspace as identity provider

Console sign in:

1. Google Cloud console, APIs and Services, Credentials: create an OAuth client of type
   **Web application** with the redirect URI `https://mdm.example.com/auth/callback`.
2. Enter issuer `https://accounts.google.com`, client ID, secret and your Workspace domain
   in **Settings, SSO**.
3. Add the people who may use the console in **Users**, or map groups to roles.

Desktop login uses a second OAuth client of type **TVs and Limited Input devices** (device
authorization grant). See [desktop-login.md](desktop-login.md).

Other providers (Entra ID, Okta, authentik, Keycloak) work the same way with their issuer URL.

## Console users and roles

| Role | May |
|---|---|
| `admin` | everything |
| `helpdesk` | see devices (within its scope); sync, install updates, restart, shut down, lock and unlock, send a message; reset the password of, lock and unlock local accounts without admin rights on a device (accounts with uid 0, membership in `sudo`, `wheel` or `admin` or a sudoers rule are refused by the server from the inventory and by the agent); collect logs (diagnostics); reveal disk recovery keys; a remote shell only when **Settings, Security, Remote shell** allows the helpdesk. Not: scripts, lost mode, wipe, retire, software, creating or deleting accounts, configuration, Settings |
| `auditor` | read everything including the audit log and Settings, change nothing |

API tokens have their own roles, among them `metrics` ([admin-api.md](admin-api.md#tokens)).

**Users** lists console accounts: OIDC identities (email) and local accounts
(`local:<name>`, password and TOTP). A new local account gets a generated password and TOTP
secret, shown once; **Reset credentials** replaces both. Rules enforced by the server:

* At least one active administrator always remains (two while four eyes approval is on).
* Nobody can demote, disable or reset their own account. The own row in **Users** is read
  only; personal settings live in the **Profile**.
* With four eyes approval, role changes wait for a second administrator.

**Scopes.** Helpdesk and auditor accounts can be limited to device tags and directory
groups (**Scope tags**, **Scope groups**, comma separated; a device is in scope when it
carries one of the tags or its primary user is in one of the groups). Empty means every
device; admins are never limited. The server enforces the scope on the device list,
overview, compliance page, device page, commands (single and bulk), remote shell, recovery
keys, CSV exports (also packages and compliance history), the compliance history page and
the audit log with its CSV and JSON Lines exports (entries about devices in scope); a
device outside the scope is answered with 404. Pages with fleet wide data that are not
filtered (Directory, Agents, Software, Network certificates, version history, Keys) are
refused to scoped accounts. API tokens can carry scope tags too
([admin-api.md](admin-api.md#tokens)); scoped tokens get no metrics.

### Role groups

**Settings, SSO, Console roles from groups** maps groups to roles, one line each:
`group; role; tags`. Groups are directory groups by name (Google Workspace sync, SCIM) and
the OIDC `groups` claim when the provider sends one. Tags limit helpdesk and auditor roles
(admins cannot be limited). A person without an explicit console account whose groups map
to a role gets an account at sign in (marked *from directory group*); its role is derived
again on every request, so leaving the group ends access after the next directory sync. The
strongest mapped role wins. Accounts created or edited in **Users** are explicit and
ignore the mapping.

### Local admins

`limdm-server local-admin` manages local accounts from the server host, for the first
account and as break glass access when OIDC fails:

```sh
sudo -u limdm limdm-server local-admin -env /etc/limdm-server/server.env [-role admin|helpdesk|auditor] [-out FILE] add NAME
limdm-server local-admin -env FILE reset NAME      # new password and TOTP secret
limdm-server local-admin -env FILE disable NAME    # or enable
limdm-server local-admin -env FILE list
```

`add` and `reset` print the user name, a generated password and the TOTP secret
(`otpauth://` URI), or write them to a new 0600 file with `-out`. The role defaults to
`admin`. Local accounts sign in only while local login is allowed.

**Tenants.** With multi tenancy, accounts belong to one tenant or are global (super
admins); accounts added while switched to a tenant belong to it. Users lists the accounts
of the current tenant, in the global view all of them with their tenant ([tenants.md](tenants.md)).

## Profile

Every user opens the profile by clicking their name in the sidebar:

* **Language:** English or German, stored in the browser. Without a choice the browser's
  `Accept-Language` decides.
* **Local accounts only:**
  * change the password (current password required, 12 to 256 characters, and the
    password policy),
  * move TOTP to a new authenticator app: a QR code is shown, the new secret takes effect
    only after a code from the new app was entered,
  * recovery codes: ten one time codes, usable instead of a TOTP code at sign in. They are
    shown once and stored as SHA-256 hashes; the profile shows how many are left.
    Generating new codes invalidates the old ones.

Password checks in the profile count towards the same lockout as the sign in (5 failures,
15 minutes). OIDC accounts are managed by the identity provider.

## Directory

**Directory** (its own page, not a Settings tab) connects people and groups:

* **SCIM 2.0** at `<LIMDM_PUBLIC_URL>/scim/v2` (filters: `attribute eq "value"` only, others
  are answered with 400 `invalidFilter`; no ETags) with a bearer token created on the page
  (Okta, Microsoft Entra ID, authentik, JumpCloud).
* **Google Workspace:** a service account with domain wide delegation for the scopes
  `admin.directory.user.readonly`, `admin.directory.group.readonly` and
  `admin.directory.group.member.readonly`, plus an admin email to impersonate. The service
  account key is stored encrypted. Synced hourly and on demand.
* **Groups** select blueprints with a priority; **People** lists the synced users.

How groups select blueprints and what deactivation does: [concepts.md](concepts.md#directory).

## Password policy

**Settings, Security, Password policy** sets the rules for passwords chosen in the console:
initial and reset passwords of local accounts on devices, and the passwords of local
console accounts. The minimum length is 12 to 128 characters (default 12); uppercase,
lowercase, digit and special character can be required, and the user name can be ruled out.
Generated passwords (new local console accounts, resets) are random and not affected.
Passwords people set on their devices follow the compliance check `accounts.pwquality`.
