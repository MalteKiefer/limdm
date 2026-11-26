# Keys

Every private key of LiMDM, where it lives, how to move it into an HSM, and how to rotate
each one without enrolling the fleet again.

## Inventory

| Key | Purpose | Algorithm | Where | Backup |
|---|---|---|---|---|
| Device CA (`ca`) | issues the agents' mTLS client certificates and the certificate of the agent listener; agents pin it | ECDSA P-384, certificate 15 years | `LIMDM_CA_DIR/<name>.crt` and `<name>.key` (0600), or the HSM | yes, with the CA directory |
| Network CA (`network-ca`) | issues EAP-TLS device certificates and signs the network CRL ([network.md](network.md)) | ECDSA P-384, 15 years | as above | yes |
| Command key (`command`) | signs commands and library items; the audit chain key is derived from it | Ed25519 | `LIMDM_CA_DIR/<name>.key` (0600), or the HSM | yes |
| Audit chain keys | HMAC-SHA256 of the audit log ([security.md](security.md#audit-log)) | derived with HKDF from the command key | derived; earlier segments in `LIMDM_CA_DIR/audit-keys` (0600) | yes, `audit-keys` and `audit-keyed-from` |
| Session key | signs console sessions and CSRF tokens, derives the AES-256-GCM keys for sealed values (OIDC client secret, Google service account key, notification channel secrets, LUKS recovery keys, desktop login client secret) and the compliance webhook key | 32+ random bytes | `LIMDM_SESSION_KEY` in `server.env` or `.env` | yes, apart from the database |
| Release key | signs `SHA256SUMS` of agent releases; its public half is compiled into the agent | Ed25519 | CI secret `RELEASE_SIGNING_KEY`, an offline file, or the HSM ([operations.md](operations.md#release-key)) | offline |
| Console TLS key | HTTPS of the console | any | `LIMDM_TLS_KEY` or the reverse proxy | as usual |

The agent listener certificate is issued by the device CA at every start (one year, renewed
a month before expiry) and is not stored.

`LIMDM_CA_DIR/keys.json` names the active key of each kind and, while a rotation runs, the
retiring one. Without the file the names are `ca`, `network-ca` and `command`, which are the
files every installation before 0.16 has. A key file never goes into the database: whoever
can only write to the database can neither issue certificates nor make devices run commands.

With several server instances the CA directory must be the same on all of them (shared
volume or copied after every rotation step).

## Key provider and HSM

`LIMDM_KEY_PROVIDER` selects where the private keys of the device CA, the network CA and the
command key live:

* `file` (default): PEM files in the CA directory, created on first start, mode 0600. The
  server refuses a key file readable by group or others.
* `pkcs11`: a PKCS#11 token (YubiHSM 2, SoftHSM, Nitrokey HSM, Thales Luna, AWS CloudHSM,
  any module with PKCS#11). The server only asks the token to sign; the keys never leave it.
  Certificates stay files in the CA directory.

| Variable | Meaning |
|---|---|
| `LIMDM_KEY_PROVIDER` | `file` or `pkcs11` |
| `LIMDM_PKCS11_MODULE` | path of the module, for example `/usr/lib/softhsm/libsofthsm2.so` |
| `LIMDM_PKCS11_TOKEN` | token label |
| `LIMDM_PKCS11_PIN` | user PIN (keep `server.env` root only) |

Keys are found by label `limdm-<name>`: `limdm-ca`, `limdm-network-ca`, `limdm-command`, and
after a rotation the names from `keys.json`. They must exist before the server starts; the
server creates the CA certificates itself. The CAs need ECDSA P-256 or P-384, the command key
Ed25519 (PKCS#11 3.0 `CKM_EDDSA`, supported by SoftHSM 2.5+, YubiHSM 2 and most current HSMs).
The audit chain key comes from a deterministic Ed25519 signature over a fixed label, since
an HSM key has no readable seed; the server checks at start that the token signs
deterministically.

### Separate build

The release binaries are static (`CGO_ENABLED=0`) and have no PKCS#11 support; with
`LIMDM_KEY_PROVIDER=pkcs11` they refuse to start with "needs a server built with -tags
pkcs11". PKCS#11 needs cgo (the module is a shared library) and one extra dependency
(`github.com/miekg/pkcs11`):

```sh
CGO_ENABLED=1 go build -tags pkcs11 -trimpath -ldflags "-s -w" -o limdm-server ./cmd/limdm-server
```

The binary links glibc dynamically. For a container, build in `golang:1.27` (Debian, with
gcc) and run on `gcr.io/distroless/base-debian12:nonroot` (it has glibc, the static image
does not), copy the module of your HSM into the image or mount it, and pin both images by
digest like `Dockerfile` does.

### SoftHSM test

Not part of the automated tests. To try the provider:

```sh
softhsm2-util --init-token --free --label limdm --so-pin 1234 --pin 5678
M=/usr/lib/softhsm/libsofthsm2.so
pkcs11-tool --module $M --token-label limdm --login --pin 5678 --keypairgen --key-type EC:secp384r1 --label limdm-ca
pkcs11-tool --module $M --token-label limdm --login --pin 5678 --keypairgen --key-type EC:secp384r1 --label limdm-network-ca
pkcs11-tool --module $M --token-label limdm --login --pin 5678 --keypairgen --key-type EC:edwards25519 --label limdm-command
LIMDM_KEY_PROVIDER=pkcs11 LIMDM_PKCS11_MODULE=$M LIMDM_PKCS11_TOKEN=limdm LIMDM_PKCS11_PIN=5678 \
  LIMDM_CA_DIR=/tmp/limdm-ca ./limdm-server serve
```

Check that `ca.crt` and `network-ca.crt` appear, enroll a test device, send it a command and
run `limdm-server audit verify` on an export.

### Moving existing keys into an HSM

The provider applies to all keys at once; one installation cannot mix file and HSM keys.
Import the current file keys (the names in `keys.json`, no rotation running) into the token
under their labels, for example `pkcs11-tool --write-object ca.key --type privkey --label
limdm-ca` (convert the Ed25519 seed of `command.key` to PKCS#8 first if the token wants it),
check that the public keys match, set `LIMDM_KEY_PROVIDER=pkcs11`, restart, and delete the key
files and their backups. Keys created in the HSM from the start never exist outside it: rotate
each kind after the switch to get there.

### Vault Transit

Not supported. A Vault Transit provider was left out to keep the dependency and code surface
small; Vault users can use Vault's PKCS#11 provider (Vault Enterprise) or an HSM.

## Rotation

A rotation has two steps, `rotate` and `finish`, from the console (**Settings, Security,
Keys**, global admins without a device scope; tenant accounts do not see the card) or the command line:

```sh
limdm-server keys -env /etc/limdm-server/server.env status
limdm-server keys -env /etc/limdm-server/server.env rotate ca            # or network-ca, command
limdm-server keys -env /etc/limdm-server/server.env finish ca            # when status shows every device moved
limdm-server keys -env /etc/limdm-server/server.env rotate session       # prints the new LIMDM_SESSION_KEY
```

Every step is written to the audit log (`keys.rotate`, `keys.finish`, `keys.reseal`,
`audit.key_rotate`) and sends the notification event `keys.rotate`. A step changes
`keys.json` and takes effect when **every server instance has restarted**; the console shows
"restart required" until then. With an HSM `rotate` needs `-name NAME` (console: the name
field), and the key `limdm-NAME` must exist in the token. `finish` refuses while devices
still depend on the old key; `-force` (console: force) finishes anyway, and those devices
must enroll again. Agents must run 0.16 or newer for a rotation: older agents never report
the new key and keep `finish` waiting.

With several instances ([high-availability.md](high-availability.md)) every step also
records the key fingerprints in the database. Between `rotate` and `finish` an instance
starts with the old or the new CA directory; after `finish` an instance whose directory
still holds the old keys refuses to start. A step waits while an instance starts.

### Device CA

1. `rotate ca` creates a new CA. After the restart it issues every new and renewed client
   certificate. The agent listener keeps its certificate from the old CA and new
   enrollments keep pinning the old fingerprint, since not every agent trusts the new CA yet.
   Both CAs are trusted for client certificates.
2. At each check in the server sends agents the bundle of both CAs over the mTLS channel; the
   agent accepts it only if it contains a CA it trusts already, stores it in
   `/etc/limdm/ca.crt` and uses it at once. A device whose certificate is from the old CA is
   asked to renew right away.
3. The console counts a device as moved when its certificate is from the new CA and it has
   confirmed the bundle. Wait for all, including laptops that are rarely online.
4. `finish ca`, restart. The listener certificate now comes from the new CA, the old CA is
   no longer trusted, its key file is deleted, and the next check in gives agents a bundle
   with the new CA only. The enrollment page and `install.sh` show the new fingerprint.

### Network CA

1. `rotate network-ca`. After the restart new EAP-TLS certificates come from the new CA;
   devices with a certificate of the old CA renew at once. `/network/ca.pem` serves both CAs
   and `/network/crl.pem` a CRL for each.
2. Install the bundle from `/network/ca.pem` on every RADIUS server (both CAs trusted), and
   let its CRL fetch job continue.
3. The console counts valid network certificates of the new CA. When all are moved:
   `finish network-ca`, restart, and replace the bundle on the RADIUS servers with the new CA.

### Command key

1. `rotate command`. After the restart the new key signs commands and library items (items
   signed by the old key are signed again at start), and the audit chain starts a new
   segment keyed from the new key (`audit.key_rotate`). The first process that starts with
   the new key records the segment, a server or a later `limdm-server keys` call; from then
   on an instance that still runs the old key can no longer write audit entries until it
   restarts. Restart every instance right after `rotate command`.
2. Every check in carries the new public key with a rollover record signed by the old key.
   The agent verifies it against its pinned key and pins the new key; commands signed by the
   old key stay valid for 14 days. A rollover not signed by the pinned key is refused and
   reported as an event.
3. The console counts devices that report the new key. When all are moved: `finish command`
   (refused until a server has started with the new key), restart. The old key file is
   deleted; its audit key stays in `audit-keys`, so old entries remain verifiable.

### Session key

1. `rotate session` prints `LIMDM_SESSION_KEY=<new>,<old>`. Put that into the environment
   and restart. The first key seals and signs, every listed key opens and verifies, so
   nobody is signed out and nothing becomes unreadable.
2. After the start the server seals every value again with the new key in the background
   (OIDC client secret, Google key, notification channel secrets, recovery keys, desktop
   login client secrets in library items and their version history) and records
   `keys.reseal`. The console and `keys status` show how many values are left.
3. `finish session` confirms that nothing depends on an old key. Then keep only the first
   key in `LIMDM_SESSION_KEY` and restart.

The compliance webhook signature key derives from the first session key: give webhook
receivers the new secret (Settings, Notifications) after step 1.

### Release key

Create a new key (`limdm-server keygen` or in the HSM), build and roll out an agent release
that trusts the new public key while still signed with the old one, then sign later releases
with the new key. `limdm-server sign -pkcs11 LABEL SHA256SUMS` signs with an Ed25519 key in
the token (`LIMDM_PKCS11_*` as above).

## Compromise

Act on the key that leaked; the order matters when several did.

* **Device CA key.** Someone can issue client certificates and a listener certificate that
  agents trust. Rotate the CA now, push agents to check in (they poll every minute), and
  finish as soon as the moved count allows, with `force` if needed: until `finish` the old
  CA stays trusted. Check the audit log for enrollments and renewals you do not know. If the
  attacker could also reach the agent port path, treat devices as possibly commanded and
  review `command.result` entries.
* **Command key.** Someone can sign commands and items devices accept, and compute audit
  hashes. Rotate the command key at once; the rollover still needs the old key, which the
  attacker has too, so finish as soon as devices moved and review commands and audit
  entries since the suspected time. Entries keyed with the old key can be forged by the
  attacker; entries of the new segment cannot.
* **Network CA key.** Rotate the network CA, deploy the new bundle to RADIUS, finish with
  `force` once the important devices have new certificates, so RADIUS stops trusting the
  old CA.
* **Session key.** Someone can forge console sessions and open sealed values from a database
  copy. Rotate the session key, then also change what was sealed: OIDC client secret at the
  identity provider, Google service account key, notification channel secrets, desktop login
  client secret, and rotate LUKS recovery keys from the device pages.
* **CA directory or HSM PIN.** Treat all keys above as leaked.
* **Release key.** Remove the CI secret, rotate as above, and publish a notice: agents with
  the old public key accept anything signed with it until updated.

Keep the old backups of the CA directory until the rotation is finished, then destroy them:
a backup with a retired key is as sensitive as the key.
