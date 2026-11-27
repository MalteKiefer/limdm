# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/MalteKiefer/limdm/security/advisories/new).
Do not open a public issue, pull request or discussion for it.

Include the affected version (server, agent or both), a description of the issue, its
impact and steps to reproduce it. You will get an answer within five working days.

## Supported versions

| Version | Security fixes |
|---|---|
| 0.20.x | yes |
| older than 0.20 | no |

Only the latest release line receives security fixes.

## Release integrity

Every release asset (archives, `.deb`, `.rpm`, checksums, the agent install script) and the
server container image `ghcr.io/maltekiefer/limdm-server` carry a GitHub build provenance
attestation signed with Sigstore. Archives and packages come with an SPDX SBOM.

```sh
gh attestation verify limdm-agent_<version>_amd64.deb --repo MalteKiefer/limdm
gh attestation verify oci://ghcr.io/maltekiefer/limdm-server:<version> --repo MalteKiefer/limdm
```

Agent self updates are additionally signed with an Ed25519 release key: the release
workflow signs the `SHA256SUMS` file, and the public half is compiled into the agent. The
private key is a CI secret of the protected `release` environment (required reviewers, tag
ruleset), not an offline key: whoever can approve a release run can sign. The release
workflow fails when the key or the public key is missing. Agents refuse unsigned or wrongly
signed releases and downgrades; an agent built without a public key (for example a local
`make build`) refuses every self update.

## Security model

See [docs/security.md](docs/security.md) for the trust model: mTLS with a pinned device CA,
signed commands, certificate rotation and revocation, OIDC with optional MFA for
administrators, four eyes approval, the keyed hash chained audit log, key rotation and HSM
support, and data minimisation. Key handling and the compromise procedure are in
[docs/keys.md](docs/keys.md).
