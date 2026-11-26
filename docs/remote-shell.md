# Remote shell

An interactive terminal from the console to a device, for support. Off by default; every
session is audited and its output is recorded.

## Requirements

A session needs all of these:

1. **The device opted in at enrollment:** `allow_remote_shell = true` in `enroll.conf`,
   `LIMDM_ALLOW_REMOTE_SHELL=true` for the install script or `--allow-remote-shell` for
   `limdm-agent enroll` ([agent.md](agent.md)). It is stored in `/etc/limdm/agent.json` and
   cannot be switched on from the server.
2. **The server allows it:** **Settings**, **Security**, **Remote shell**:

   | Setting | Default | |
   |---|---|---|
   | Allow remote shells (admins) | off | admins may start sessions |
   | The helpdesk role may start sessions | off | |
   | Sessions may run as root | off | otherwise `root`, every other account with UID 0 and every account with admin rights (member of `sudo`, `wheel` or `admin`, or named in a sudoers rule directly or through a `%group`, `NOPASSWD` rules included) are refused, by the server from the inventory and by the agent |
   | Maximum duration (minutes) | 60 | 5 to 480 |
   | Idle timeout (minutes) | 15 | 1 to 120 and not longer than the maximum; no keyboard input from the console |

   The settings are global. With multi tenancy, tenant admins (and tenant helpdesk accounts
   when allowed) start sessions on the devices of their tenant
   ([tenants.md](tenants.md#tenant-accounts)).

3. **Approval** (optional): with **Settings**, **Security**, **Four eyes approval** and
   **Also for remote shell sessions** on, the first start files a request under
   **Approvals** ([security.md](security.md#four-eyes-approval)) and the shell page says
   **The session waits for approval.** Once another admin approves it, the requester
   starts the session within one hour; the approval is used up by that start. This applies
   to helpdesk accounts as well.
4. **Scope**: helpdesk and auditor accounts limited to device tags or groups can open the
   shell page, start sessions, connect and read transcripts only for devices in their
   scope. The admin API cannot start shells (`shell` is no API command type).

Auditors never start sessions.

## Starting a session

Device page, **More actions**, **Agent**, **Remote shell…** (admins), or **Remote shell
sessions** on the **Commands** tab. The page lists the sessions of the device and shows the
limits from the settings; **Start session** starts one. Leave **Local user** empty for the
support account `limdm-support` (a system account with a locked password and the home
`/var/lib/limdm-support`, created on first use, not in any admin group) or name an existing local account. The page opens the terminal and waits
for the device: it receives the command with its next poll, at most about a minute later,
and the session gives up after three minutes.

## How it works

```
browser ──WebSocket (console listener, session cookie)──▶ server ◀──HTTPS POST (agent listener, mTLS)── agent ── PTY ── runuser -l <user>
```

1. The server stores the session (random 256 bit ID) and queues the signed command `shell`
   with the session ID, the account, the requesting console user and the limits.
2. The agent verifies the signature like every command and additionally requires a pinned
   command key, `allow_remote_shell`, a command younger than 10 minutes, a valid payload
   and an existing account (UID 0 and accounts with admin rights only when the server setting allows root). One session
   runs at a time.
3. The agent opens `POST /api/v1/shell/<session>` on the agent API with its client
   certificate. No port is opened on the device. The request body carries the terminal
   output, the response streams keyboard input and window sizes (HTTP/2, both directions).
   The server accepts the connection only from the device the session belongs to.
4. The agent runs `runuser -l <account>` on a new pseudo terminal in its own session and
   process group.
5. The browser connects to `/shell/<session>/ws` on the console listener. The server checks
   the session cookie, that the user is the one who started the session and still has the
   role and setting for it, the exact `Origin` (`LIMDM_PUBLIC_URL`) and the CSRF token. One
   browser window per session. A reverse proxy in front of the console must pass WebSocket
   upgrades (Caddy does by default).

The console terminal is xterm.js, served from the console itself
(`internal/server/web/static/vendor/xterm`, MIT, exact version, see `VERSION` and
`SHA256SUMS` there); the Content Security Policy stays `default-src 'self'`. When the files
are missing in a build, the page says so: run `scripts/vendor-xterm.sh` and rebuild.

## On the device

* The signed in desktop user gets a critical notification when the session starts (who, as
  which account, how long at most) and another when it ends. The tray shows **IT remote
  support session running** while it runs, `limdm info` names it.
* The user ends it with `limdm support end`. Typing `exit` in the terminal ends it too.
* The agent ends the session at the maximum duration and after the idle timeout, and then
  hangs up the whole process group (SIGHUP, SIGKILL after three seconds): background jobs
  started in the session end with it.

## Ending a session

Either side can end it: **End session** in the console (the user who started it or an
admin), closing the browser window, `limdm support end` or `exit` on the device, the
limits, or the server when the console user is disabled or loses the role or setting
(checked every minute). A session that ended before the device picked it up expires its
command.

## Audit and transcripts

* The audit log records `shell.start` (console user, device, session, account) and
  `shell.end` (reason, amount of output).
* The device keeps events in its log (`remote shell as … opened by …`, `… ended: …`).
* The server stores the terminal output of every session, up to 1 MiB (marked
  `truncated` beyond), for 365 days like device events. Input is not stored separately:
  what the shell echoes is in the output, password prompts without echo are not.
* **Transcripts** are shown to admins and auditors (device page, **Remote shell
  sessions**, **Open**) with control sequences removed. The helpdesk role sees only its own
  sessions and no transcripts.

## Limits

* With several server instances a session lives on the instance that started it. Console
  and device may reach any instance; the others relay to it over PostgreSQL notifications
  ([high-availability.md](high-availability.md#remote-shell)). Keystrokes and output then
  pass through PostgreSQL's notification queue (not written to tables or the WAL).
* Stopping an instance cleanly (SIGTERM) ends the sessions it holds or relays and stores
  their transcripts. A crash ends running sessions; they are listed as `interrupted` and
  have no `shell.end` entry.
* Accounts are looked up in `/etc/passwd` (the agent is built without cgo); directory
  accounts that exist only through NSS cannot be chosen.
