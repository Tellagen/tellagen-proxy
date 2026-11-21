# Changelog

All notable changes to this project are in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `grafana.list_alert_rules` returns more of each rule when Grafana reports it: the threshold (`gt`, `lt`, `within_range`, `outside_range` or `no_value`), how long the condition must hold (`for`), the labels, when the rule was last saved (`updated`), its `version` and the datasource of its query. The details are read for the first 5 rules of a list, within half of the command's time; a list that came back is never turned into a timeout by them. A threshold is given only with the query it judges, so a rule whose condition passes through a math node gets neither. A field Grafana does not report is left out, and an older reader ignores the new fields.
- A new read-only capability, `grafana.alert_rule_versions`, returns the version history of one alert rule (up to 20 versions, newest first) with the time, the expression and the threshold of each. It needs Grafana 12 or later, and answers with a clear error where the endpoint does not exist or the rule is not found.

## [1.0.0] - 2026-11-15

### Added

- The proxy lives in its own public repository: the Go code, the `protocol` and `redact` packages, the Helm chart, and the release workflow.
- Images for linux/amd64 and linux/arm64 on `ghcr.io/tellagen/tellagen-proxy`, signed with cosign (keyless), with an SBOM and build provenance.
- The Helm chart at `oci://ghcr.io/tellagen/charts` and at the repository `https://charts.tellagen.com`.
