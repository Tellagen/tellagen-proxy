# Changelog

All notable changes to this project are in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The proxy lives in its own public repository: the Go code, the `protocol` and `redact` packages, the Helm chart, and the release workflow.
- Images for linux/amd64 and linux/arm64 on `ghcr.io/tellagen/tellagen-proxy` and `docker.io/tellagen/tellagen-proxy`, signed with cosign (keyless), with an SBOM and build provenance.
- The Helm chart at `oci://ghcr.io/tellagen/charts` and at the repository `https://charts.tellagen.com`.
