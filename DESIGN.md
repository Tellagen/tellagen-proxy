# Design

This document is for a reader who wants to audit tellagen-proxy: what it is allowed to do, how a command moves through it, and what can go wrong. File and package names point to the code that backs each claim.

## Purpose and trust model

Tellagen diagnoses incidents with an AI. Some Grafana instances are not reachable from the internet. The proxy runs inside the customer's network, reaches both Tellagen and Grafana, and lets Tellagen run a small set of read-only queries.

The trust model has three parts:

- **The customer trusts the proxy, not Tellagen's AI.** Tellagen can ask for a query, but the proxy decides whether it runs. The decision uses the proxy's own code and the customer's local policy file. The file sets the highest limits, up to the ceilings built into the binary (`logs.maxScanBytes` has no ceiling). Tellagen can lower them and choose the datasources, log lines and redaction inside them, and can never go above them.
- **The proxy trusts Grafana only as a data source.** Grafana's answers are reduced and redacted before they leave the network.
- **The proxy trusts Tellagen to authenticate.** Every request carries a token. Tellagen never connects to the proxy: there is no inbound path.

The proxy contains no AI, no model client and no MCP server. It links the tool code of [grafana-mcp](https://github.com/grafana/mcp-grafana) as a library and calls ten tool handlers directly, in process.

## Data flow

```text
 customer network                                      Tellagen
+------------------------------------------+      +------------------+
|                                          |      |                  |
|  Grafana <-- GET, POST /api/ds/query --  |      |                  |
|              tellagen-proxy -------------+----->|  connect.        |
|                  ^                       |      |  tellagen.com    |
|                  |  /healthz /readyz     |      |                  |
|                  |  /metrics             |      +------------------+
|        the only listener                 |
+------------------------------------------+
 The proxy opens every connection: session, hello, poll, result.
```

1. The proxy trades its token for a short-lived session, says hello, and polls.
2. A poll answer holds zero or more messages: a command, a cancel, or a policy update.
3. For a command the proxy checks, runs, reduces and redacts, then posts one result.
4. The poll is also the heartbeat. Tellagen sees the proxy go away when the polls stop.

## The command pipeline

Every command passes the same stages, in this order, and a refusal at any stage ends it with a result that names the reason. The policy checks and the guard run together in `admit`, before any call to Grafana. The code is in `internal/executor/executor.go` (`execute`, `admit`, `finish`).

```text
command --> policy --> guard --> read-only call --> reduce --> redact --> cut and fit --> result
```

| Stage | What it does | Code |
| --- | --- | --- |
| Policy | Refuses a capability that the policy file does not offer, a version it does not have, a datasource that is not allowed, and a run that used up its query count. Limits are the smallest of the binary, the policy file, Tellagen's narrowing and the command. | `internal/policy` |
| Guard | Parses the PromQL or LogQL expression and checks it by its syntax tree. It refuses a query it cannot read, a range or point count above the limit, and a LogQL stage that could rewrite or leak text. | `internal/guard` |
| Read-only call | Runs one grafana-mcp handler. The HTTP layer below it pins the Grafana host, allows `GET`, allows `POST` only on `/api/ds/query`, and follows no redirects. A response over 32 MiB fails. | `internal/executor/transport.go` |
| Reduce | Turns Grafana's answer into named fields, at most the allowed series and points, with statistics over each whole series. | `internal/reduce` |
| Redact | Removes emails, IP addresses, tokens, keys and card numbers, secret-looking fields, and the matches of the policy's extra rules. It runs before any cut, so a secret is never cut in half before it is seen. | `redact` |
| Cut and fit | Cuts long lines and labels, and drops items until the result fits the byte limit. The result says it was truncated. | `internal/reduce` |

Two details matter for an audit:

- **Deny by default for data.** Until Tellagen sends a policy update, no datasource is allowed, log lines are off, and redaction is on (`policy.NewEngine`). The policy file can limit the datasources further, but it can never allow what Tellagen has not chosen.
- **A fixed set of tools.** `allowedTools` in `internal/executor/tools.go` names ten grafana-mcp tools one by one. There is no generic API tool, no SQL tool and no capability that takes a URL. `tools.lock.json` pins the input schema of each tool and the version of grafana-mcp. The proxy refuses to start if any tool changed or is not marked read-only.

The audit line of a command (`internal/agent/audit.go`) holds the query, the datasource, the outcome and the redaction counts. It holds no token and no result data.

## Packages

| Package | Owns |
| --- | --- |
| `cmd/tellagen-proxy` | The command line (no argument runs the proxy, plus `doctor` and `version`) and the wiring of the other packages. |
| `protocol` | The wire types, the token format, the capability catalog with its limits, and the result types. Public. It imports only the standard library. |
| `redact` | The redaction rules. Public, so Tellagen can run the same rules on receipt. |
| `internal/settings` | Environment variables, secret files with rotation, and the HTTP transports for Tellagen and for Grafana. |
| `internal/hub` | The client of the Tellagen routes: session, hello, poll, result, and the classification of errors. |
| `internal/agent` | The main loop: hello, poll, the backoff plan, command goroutines, audit lines, and the health endpoint with its metrics. |
| `internal/executor` | The pipeline above, the tool list and its lock file, and the read-only transport. |
| `internal/policy` | The policy file, and the narrowing that Tellagen applies inside it. |
| `internal/guard` | The PromQL and LogQL checks. |
| `internal/reduce` | Reducing, cutting and fitting results. |
| `internal/grafana` | The few direct Grafana calls for the hello and the doctor: health, version, datasources, the token's role and a test query. |
| `internal/doctor` | `tellagen-proxy doctor`: the checks, the report and the short summary in each hello. |
| `tools/licenses` | Collects the license text of every dependency for the image, and fails on a license the image must not carry. |

## Wire protocol

The types are in `protocol`, and the JSON of every message is pinned by golden files in `protocol/testdata`. A message cannot change without a new protocol version. The proxy only makes requests. All routes are `POST` under `/api/proxy/v1`, with a `Bearer` token and HTTP/1.1.

1. **`/session`.** The proxy sends its proxy token (`tlg_proxy_<id>.<secret>`) and gets a session token (`tlg_psess_…`) and its expiry. The session lives in memory only. The proxy renews it a minute before it ends, and after a `401` that says `proxy_session_invalid`.
2. **`/hello`.** The proxy reports its version, the protocol versions it speaks, its instance id and labels, its capabilities with their highest limits and a digest of them, the policy revision and what the policy capped, the executor, a short doctor summary, and the Grafana source with its datasources. The reply carries the poll settings and the current policy. The session decides the workspace. The proxy never sends a company id.
3. **`/poll`.** The proxy says how many command slots are free, which commands are in flight, the policy revision it applied and the health of its source. Tellagen holds the request for 25 seconds unless its hello reply sets another wait, and answers with messages:
   - `command`: a capability and its version, typed arguments, limits, a deadline and a lease. It carries an `attempt_token` that the result must echo.
   - `cancel`: stop a running command.
   - `policy_update`: the choices an admin made in Tellagen. A message of an unknown type is ignored.
4. **`/commands/{id}/result`.** One result per command with a status (`ok`, `partial`, `rejected`, `error`, `cancelled`), the reduced data, the redaction counts, a fingerprint of the query and a link to Grafana Explore when a public address is set. A result Tellagen no longer wants gets `409` or `410`, and the proxy drops it.

Errors from Tellagen use the codes in `protocol.ErrorReply` (`proxy_token_invalid`, `proxy_revoked`, `proxy_upgrade_required` and others).

## Configuration and secrets

[docs/configuration.md](docs/configuration.md) lists every variable. These rules shape the code in `internal/settings`:

- **Secrets come from the environment or from a file, never both.** A token in a file is read again every minute, so a rotated token needs no restart. The proxy token is also read again after a `401` from Tellagen. A Vault sidecar may write the file late, so the proxy waits up to two minutes for it at start.
- **A token never leaves its host.** The proxy token goes only to `TELLAGEN_URL`. The Grafana token goes only to `GRAFANA_URL`. The Grafana address itself is never sent to Tellagen: the hello carries only `GRAFANA_PUBLIC_URL`.
- **Settings fail loudly.** `settings.Load` collects every problem and the proxy exits with the list. A policy file with an unknown key or a bad value also stops the start, so a typo never becomes a looser limit.
- **Transports are strict.** Both connections verify certificates, use TLS 1.2 or later, and trust the system roots plus an optional company CA. Tellagen traffic uses HTTP/1.1 and the proxy settings of the environment. Grafana traffic is direct unless `GRAFANA_HTTPS_PROXY` is set.
- **The policy file** (`internal/policy/file.go`) sets the highest limits, the datasources, the capabilities, the log matchers that are added to every Loki selector, and whether redaction may be turned off. The policy revision in the hello, the poll and each audit line is the revision of Tellagen's latest policy update, and it is empty before the first one.

## Failure modes

| What fails | What the proxy does |
| --- | --- |
| Grafana is down or slow | A command ends with `source_unavailable` (retryable) or `timeout`. The proxy keeps running, and `/readyz` stays ready, because it reflects Tellagen, not Grafana. It checks Grafana every five minutes and reports the health in each poll. |
| Tellagen is down or unreachable | Failed calls back off from one second to 30 seconds, with 20 percent jitter. After 60 seconds without an answer `/readyz` answers `503`, and `/healthz` stays `ok`, so a Tellagen outage does not restart a pod. Running commands finish, and a result is sent up to six times. After that Tellagen sends the command again when its lease ends. A `429` makes the proxy wait for the `Retry-After` header, at most five minutes. |
| A corporate proxy cuts held requests | Two cut polls in a row lower the wait from 25 to 10 seconds, two more switch to short polls every two seconds, and after ten minutes the proxy tries the full wait again. The mode is a metric. |
| The token is revoked, invalid or too old a version | The proxy logs one clear line, waits with a growing delay up to five minutes, and tries again, because the token file may hold a new token by then. |
| The settings or the policy file are bad | The proxy exits with code 1 and prints every problem. `doctor` shows the fix for each. |
| The grafana-mcp tools changed | The executor refuses to start (see the lock file above). |
| A command panics | The panic becomes an error result for that one command. |
| Shutdown (`SIGTERM`) | The proxy stops polling, lets commands finish for ten seconds, cancels the rest, and sends the cancelled results. |

## Observability

- `GET /healthz`, `GET /readyz` and `GET /metrics` on `TELLAGEN_HEALTH_ADDR` (`internal/agent/health.go`). The metrics use a private registry: only the proxy's own series appear.
- One JSON log line per event on standard error, and one JSON audit line per command on standard output.
- `tellagen-proxy doctor` checks the settings, DNS, TCP, TLS, any corporate proxy, the clock, the token, the version, the state of the running proxy and Grafana. A short form runs for each hello and goes into it.

## Versioning and compatibility

- **Protocol.** The proxy offers `protocol.ProtocolVersion` in its hello. Tellagen answers `426` with `proxy_upgrade_required` and a minimum version when the proxy is too old.
- **Capabilities.** The hello lists each capability with a version and a digest of the list. The proxy refuses a command for a capability it does not offer or for a capability version it does not have. A capability this build does not know is not an error: Tellagen simply never asks for it.
- **Unknown messages.** A poll message of an unknown type is ignored, so a newer Tellagen can add messages without breaking an older proxy.
- **Go API.** The packages `protocol` and `redact` are public and stable. Tellagen imports them for its side of the protocol. Everything under `internal` is private to this repository.
- **Releases** follow semantic versioning. The version is set at build time (`-X main.version`) and shows in `tellagen-proxy version`, the hello, the user agent and the `tellagen_proxy_build_info` metric.

## Release

A release is a `v*` tag on a commit that is on `master`. The release workflow (`.github/workflows/release.yml`) first runs the CI workflow, then:

1. Builds the image for `linux/amd64` and `linux/arm64`, with an SBOM and build provenance, and pushes it to `ghcr.io/tellagen/tellagen-proxy`.
2. Copies it to `docker.io/tellagen/tellagen-proxy`. A stable release also gets the moving tags for its major and its major.minor version. A pre-release (`-rc`, `-beta`) never does.
3. Signs both images by digest with cosign keyless signing and verifies the signature against the identity of this workflow.
4. Packages the chart with the version of the tag and the digest of the signed image, pushes it to `oci://ghcr.io/tellagen/charts`, and signs it.
5. Adds the chart to the classic repository at `https://charts.tellagen.com`, which is a GitHub Pages site. The job downloads the versions in the live index first, so the new index keeps them. A missing index means the first release, and any other answer stops the job.
6. Creates a GitHub Release with the notes from `CHANGELOG.md`.

The Docker Hub credentials live in the `release` environment, so, with the environment limited to `v*` tags, only a run of the release workflow can read them. The chart in the repository keeps the placeholder version `0.0.0`. Tellagen shows the newest released version in its setup commands. It keeps that value on its own side, and for now it is updated by hand after a release.

## Non-goals

- Writing to Grafana, or running any query that changes state.
- Any inbound connection from Tellagen, or any listener other than health and metrics.
- Running a model, an agent loop or an MCP server.
- Storing data. The proxy keeps no database and no cache of results. It keeps only counters for the runs it has seen in the last 24 hours, to enforce the per-run limits.
- Reaching more than one Grafana. Run one proxy for each Grafana.
