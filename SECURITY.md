# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/MalteKiefer/limdm/security/advisories/new).
Do not open a public issue.

Include the affected version, a description of the issue and steps to reproduce it.
You will get an answer within five working days.

## Supported versions

Only the latest release receives security fixes.

## Release integrity

Every release asset (archives, `.deb`, `.rpm`, checksums) carries a GitHub build
provenance attestation signed with Sigstore, and an SPDX SBOM:

```sh
gh attestation verify limdm-agent_<version>_amd64.deb --repo MalteKiefer/limdm
```

Agent self updates are additionally signed with an Ed25519 release key whose
public half is compiled into the agent. The private key is a CI secret of the
protected `release` environment (required reviewers, tag ruleset), not an
offline key: whoever can approve a release run can sign. The release workflow
fails when the key or the public key is missing. Agents refuse unsigned or
wrongly signed releases and downgrades; an agent built without a public key
(for example a local `make build`) refuses every self update.

## Security model

See [Security](README.md#security) in the README for the trust model: mTLS with
a pinned device CA, certificate rotation and revocation, OIDC for administrators,
append only hash chained audit log and data minimisation.
