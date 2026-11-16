# Changelog

All notable changes to this project are in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The `diagnosis-reader` Helm chart at `oci://ghcr.io/tellagen/charts/diagnosis-reader`. It installs a read-only Kubernetes role (`get`, `list` and `watch`, never secrets, `pods/exec` or other writes) and binds it to groups, or to a service account whose tokens the groups can create. It has a Helm test and a kind test in CI.

## [1.0.0] - 2026-11-15

### Added

- The proxy lives in its own public repository: the Go code, the `protocol` and `redact` packages, the Helm chart, and the release workflow.
- Images for linux/amd64 and linux/arm64 on `ghcr.io/tellagen/tellagen-proxy`, signed with cosign (keyless), with an SBOM and build provenance.
- The Helm chart at `oci://ghcr.io/tellagen/charts` and at the repository `https://charts.tellagen.com`.
