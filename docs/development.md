# Development

Go (see `go.mod`), no cgo: every binary builds with `CGO_ENABLED=0`.

```sh
make build                                               # dist/limdm-{server,agent}-linux-{amd64,arm64}
make test                                                # unit tests
make lint                                                # golangci-lint
make integration DB=postgres://limdm@127.0.0.1:5432/limdm  # needs an empty database
make snapshot                                            # goreleaser snapshot: deb, rpm, tar.gz
```

Integration tests drop and recreate the `public` schema of the given database. Never point
them at a database with data.

## Layout

| Path | |
|---|---|
| `cmd/limdm-server`, `cmd/limdm-agent`, `cmd/limdm-desktop` | entry points |
| `internal/api` | protocol types, declaration validation, blueprint resolution and merging |
| `internal/server` | console, agent API, SCIM, directory sync, migrations (`schema.sql`, `library.go`) |
| `internal/server/web` | templates, CSS, the blueprint editor script |
| `internal/agent` | agent: enforcement, compliance checks, inventory, PAM, desktop socket |
| `packaging`, `deploy`, `scripts` | systemd units, packages, Docker Compose, Caddy, install script |

## Conventions

* Validation lives in `internal/api` and runs on server and agent.
* Console texts are English keys; German translations in `internal/server/i18n.go`. A test
  fails when a template text has no German entry.
* Commits are signed; `main` only accepts pull requests with passing checks.

## Release

1. Merge to `main`.
2. `git tag -s vX.Y.Z -m "LiMDM vX.Y.Z" && git push origin vX.Y.Z`
3. Approve the `release` environment in GitHub Actions.

The workflow runs goreleaser (packages, archives, SBOMs, checksums), attests build
provenance and publishes `ghcr.io/maltekiefer/limdm-server`.
