# Package repository

Admins upload their own packages, scripts and files under **Software, Packages** and install
them with a library item of the type **Uploaded packages** (`com.limdm.artifacts`,
[declarations.md](declarations.md#comlimdmartifacts-list)). LiMDM is no repository server:
dependencies still come from the configured package sources, as for the agent's own updates.
For a full repository (many packages, versions, `apt upgrade`), run aptly, createrepo or Pulp
and add it with `com.limdm.repositories`.

## Kinds

| Kind | File | Installed with | Families |
|---|---|---|---|
| `deb` | `.deb` | `apt-get install ./file` | Debian, Ubuntu |
| `rpm` | `.rpm` | `dnf install` / `zypper install --allow-unsigned-rpm` | Fedora, RHEL, SUSE |
| `apk` | `.apk` | `apk add --allow-untrusted` | Alpine |
| `pacman` | `.pkg.tar.zst`, `.pkg.tar.xz` | `pacman -U` | Arch |
| `flatpak` | `.flatpak` bundle | `flatpak install --system --bundle` | all with Flatpak |
| `script` | starts with `#!` | `/bin/sh file`, once | all |
| `file` | anything | written to `path` with `mode`, owner root | all |

The upload checks the start of the file against the kind (deb archive, rpm lead, gzip,
zstd or xz, `#!`). A package item may list the same software for several families; each
device installs the entries of its own family and skips the others.

Unsigned local packages are accepted by apk and zypper because the agent has already checked
the SHA-256 from the signed library item. Each upload installs once per device (by hash; a
`file` by hash and path). A new version is a new upload with a new hash. Removing an entry
does not uninstall the software; remove it with `com.limdm.packages` or a script.

## Upload

**Software, Packages, Upload**: name, version, kind, file. The server streams the file into
a temporary file (`TMPDIR`), computes the SHA-256, checks kind, size and quota and stores it
content addressed as `t<tenant>/sha256/<ab>/<hash>`. The same file twice in one tenant is
refused. The list shows every upload with its hash, the library items that use it and a
ready payload to paste into a library item.

| Setting (global admins) | Default |
|---|---|
| Upload limit | 512 MiB per file (up to 16 GiB) |
| Quota per tenant | 20 GiB and 500 files |
| Storage | local `LIMDM_ARTIFACT_DIR` (default `/var/lib/limdm-server/artifacts`) or an S3 bucket |

Uploads are held while the request runs (up to one hour). Local uploads are part of every
backup ([backup.md](backup.md)); with several server instances use S3 or a directory all
instances share. Switching the store is refused while uploads exist: delete them or copy the
objects to the new store with the same names first.

An upload can be deleted when no library item references it.

## Tenants

Every upload belongs to one tenant (`tenant_id`), stored under its own prefix, and counts
against that tenant's quota. A library item may only reference uploads of its own tenant.
Uploads of the default tenant, made by global admins, can be referenced by its items, which
reach devices of every tenant like other default tenant items. Tenant admins see and manage
only their tenant's uploads.

## Delivery and verification

1. The library item carries the SHA-256 and size inside its payload, signed with the command
   key like every item; the agent pins that key.
2. The agent downloads `GET /api/v1/artifacts/<sha256>` over the mTLS agent API. The server
   answers only when the device's own resolved declarations contain that hash and the upload
   is approved and belongs to the device's tenant or the default tenant.
3. The agent keeps the file only when its SHA-256 matches, then installs it.

With S3 the server streams the object to the device. Presigned URLs are not used: the agent
trusts only the device CA for its server connection, and the hash check makes a second
channel unnecessary.

## Who may install

Every kind runs as root: package maintainer scripts, the script itself, a file anywhere on
the system. Uploads therefore install only on devices enrolled with **`allow_scripts`**, the
same opt in remote scripts need. It is set on the device at enrollment (installer token or
`limdm-agent enroll -config`) and the server cannot switch it on; a compromised console can
not turn devices that refused scripts into ones that run uploads. A separate per device opt
in was not added: it would be a second switch with the same meaning, and one that the
server could set would be weaker. Devices without `allow_scripts` report the item as failed.

## Four eyes

With **Settings, Security, Four eyes approval** on, every upload (all kinds act as root)
waits for a second admin under **Approvals** (`artifact.upload`). Until then it is marked
**awaiting approval**, library items cannot reference it and devices cannot download it.
Saving or rolling back a `com.limdm.artifacts` library item is a second request of its own:
the upload decides what may be installed, the item decides where. The item, with the
SHA-256 of every package it names, is signed with the command key like every library item,
so a database write cannot point devices at another package.

## Audit

`artifact.upload` (name, version, kind, size, hash, file name), `artifact.delete`,
`artifact.settings`, and the approval entries. Every installation is a device event
(`installed uploaded deb vendor-vpn (3f5a...)`).
