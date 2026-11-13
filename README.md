# tellagen-proxy

tellagen-proxy connects a Grafana that Tellagen cannot reach, for example one inside a private network. It polls Tellagen over outbound HTTPS, runs read-only queries against your Grafana, and sends back small, redacted results.

[Tellagen](https://tellagen.com) uses it for Cloud diagnosis: the AI works in Tellagen, and this proxy is the only part that touches your Grafana.

## What it does and never does

- **Reads only.** Every command is one of eleven typed, read-only capabilities (Prometheus, Loki and a few Grafana lookups). A query is parsed and checked before it runs. The HTTP layer below it pins the Grafana host, allows `GET`, allows `POST` only on the Grafana query path (`/api/ds/query`), and follows no redirects.
- **Outbound only.** It opens connections to Tellagen and to your Grafana. The one port it listens on (`8080`) serves health checks and metrics.
- **Policy you control.** A local policy file sets the highest limits. Tellagen can lower them and choose what is queried, but it can never go above them. No datasource can be queried until an admin chooses one in Tellagen.
- **Redaction.** Emails, IP addresses, tokens, keys and card numbers are removed from every result before it leaves your network. A Tellagen admin can turn this off only if your policy file allows it.
- **No AI and no MCP server.** The proxy contains no model. It does not run Grafana's MCP server: it calls the tool code directly, inside the same process.
- **No secrets in logs.** It never prints a token in full. Each command writes one audit line to standard output with the query and the outcome, and no result data.

[DESIGN.md](DESIGN.md) explains how this works and how to audit it.

## Quick start

Create a proxy in Tellagen (Settings, Cloud diagnosis) to get the proxy token, and create a Grafana service account with the Viewer role to get a Grafana token. Save them as the files `tellagen-proxy-token` and `grafana-token`. The setup page in Tellagen prints these commands filled in for you.

Replace `<version>` with a release from the [releases page](https://github.com/Tellagen/tellagen-proxy/releases).

### Docker

```sh
docker run -d --name tellagen-proxy --restart unless-stopped --read-only \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/tellagen-proxy-token:/run/secrets/tellagen-proxy-token:ro" \
  -v "$PWD/grafana-token:/run/secrets/grafana-token:ro" \
  -e TELLAGEN_PROXY_TOKEN_FILE=/run/secrets/tellagen-proxy-token \
  -e GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE=/run/secrets/grafana-token \
  -e TELLAGEN_INSTALL_METHOD=docker \
  -e GRAFANA_URL='https://grafana.example.com' \
  ghcr.io/tellagen/tellagen-proxy:<version>
```

The image is also on Docker Hub as `tellagen/tellagen-proxy`. If Grafana runs on the same host, `localhost` does not work from inside the container: use `host.docker.internal` or the host's address.

### Helm

```sh
helm install tellagen-proxy oci://ghcr.io/tellagen/charts/tellagen-proxy \
  --version <version> -n tellagen --create-namespace \
  --set-string grafana.url='https://grafana.example.com' \
  --set-file tellagen.token=./tellagen-proxy-token \
  --set-file grafana.token=./grafana-token
```

The chart is also a classic repository: `helm repo add tellagen https://charts.tellagen.com`.

Helm keeps the token values in its release record. To keep them out, make the Secret first and point the chart at it:

```sh
kubectl create namespace tellagen
kubectl -n tellagen create secret generic tellagen-proxy \
  --from-file=tellagen-proxy-token=./tellagen-proxy-token \
  --from-file=grafana-service-account-token=./grafana-token

helm install tellagen-proxy oci://ghcr.io/tellagen/charts/tellagen-proxy \
  --version <version> -n tellagen \
  --set-string grafana.url='https://grafana.example.com' \
  --set existingSecret=tellagen-proxy
```

The chart also supports token files written by Vault Agent or a CSI driver (`secretFiles.*`), a corporate proxy, a company CA bundle, a policy file, a NetworkPolicy and OpenShift. Every value is in [`helm/tellagen-proxy/values.yaml`](helm/tellagen-proxy/values.yaml).

### Check the connection

```sh
docker exec tellagen-proxy /tellagen-proxy doctor
kubectl -n tellagen exec deploy/tellagen-proxy -- /tellagen-proxy doctor
```

`doctor` checks the settings, DNS, TLS and the path to Tellagen, then your Grafana and its datasources. It prints a fix for each problem and exits with 1 when a check fails. `doctor --json` prints the same report as JSON.

## Configuration

Every secret setting `X` can also come from a file in `X_FILE`. Set only one of them. A secret file is read again every minute, so a rotated token needs no restart.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TELLAGEN_PROXY_TOKEN` or `_FILE` | required | The proxy token. It starts with `tlg_proxy_`. |
| `GRAFANA_URL` | required | The address the proxy uses to reach Grafana. It never leaves your network. |
| `GRAFANA_SERVICE_ACCOUNT_TOKEN` or `_FILE` | required | A Grafana service account token with the Viewer role. |
| `GRAFANA_PUBLIC_URL` | none | The address people open, for links to Grafana. |
| `GRAFANA_ORG_ID` | none | A Grafana organization id, above zero. |
| `GRAFANA_ALLOWED_DATASOURCE_UIDS` | none | A comma-separated allowlist of datasource UIDs. Tellagen can only make it smaller. |
| `TELLAGEN_URL` | `https://connect.tellagen.com` | The Tellagen address. It must be `https`, except for `localhost`, loopback addresses and `.localhost` and `.test` names. |
| `TELLAGEN_POLICY_FILE` | none | The path of the [policy file](#policy-file). |
| `TELLAGEN_CA_FILE`, `GRAFANA_CA_FILE` | none | A PEM bundle that adds to the system roots for Tellagen and for Grafana. |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | none | A corporate proxy for traffic to Tellagen. |
| `GRAFANA_HTTPS_PROXY` | none | A proxy for traffic to Grafana. Without it, Grafana is reached directly. |
| `TELLAGEN_HEALTH_ADDR` | `:8080` | Where the health and metrics endpoint listens. |
| `TELLAGEN_LABELS` | none | Labels shown next to the proxy, such as `env=prod,cluster=prod-eu-1`. At most 16. |
| `TELLAGEN_INSTANCE_ID` | `tellagen-proxy-<hostname>` | The name of this replica. Without a host name, or on `localhost`, it ends in a random suffix. |
| `TELLAGEN_INSTALL_METHOD` | none | How the proxy was installed (`helm`, `docker`, `compose`). It is shown in Tellagen. |

The proxy refuses to start on a value it cannot use and lists every problem at once.

### Policy file

The policy file is YAML. The proxy refuses to start on an unknown key or a bad value, so a typo never becomes a looser limit. A value can be raised up to the ceiling that is built into the binary, and a larger value is cut to the ceiling. `logs.maxScanBytes` is the one limit with no ceiling in the proxy.

| Key | Default | Ceiling | Meaning |
| --- | --- | --- | --- |
| `datasourceUIDs` | none | | The datasources the proxy may query. |
| `capabilities` | all | | The capabilities the proxy offers. |
| `query.maxTimeout` | `60s` | `60s` | The longest query. |
| `query.maxPerRun` | `40` | `200` | Queries that read data in one run. |
| `query.maxListPerRun` | `60` | `60` | List and search calls in one run. |
| `query.maxConcurrent` | `2` | `2` | Queries at the same time. |
| `query.maxResultBytes` | `65536` | `65536` | The size of one result. |
| `query.maxItems` | `200` | `200` (`100` for Grafana lookups, `50` for dashboard search) | Items in a list result. |
| `metrics.maxRange` | `24h` | `7d` | The time range of a Prometheus query. |
| `metrics.maxPoints`, `metrics.maxSeries` | `500`, `20` | `500`, `50` | Points and series of a Prometheus query. |
| `logs.maxRange` | `6h` | `24h` | The time range of a Loki query. |
| `logs.maxPoints`, `logs.maxSeries` | `500`, `20` | `500`, `50` | Points and series of a Loki metric query. |
| `logs.maxLines`, `logs.maxLineChars`, `logs.maxPatterns` | `20`, `500`, `5` | `50`, `500`, `5` | Log lines, their length and patterns that a result may hold. |
| `logs.maxScanBytes` | `10737418240` | none | The most data a Loki query may scan. |
| `logs.enforcedMatchers` | none | | Label matchers added to every Loki selector. |
| `redaction.allowOff` | `false` | | Lets a Tellagen admin turn redaction off for this proxy. |
| `redaction.extraRules` | none | | More rules: `{kind: key, key: ...}` or `{kind: pattern, regex: ...}`. |

Tellagen can lower these limits, and it can choose the datasources and the number of log lines, but only inside what the file allows. A request above the file is capped, and the next hello says so.

With Helm, put the same keys under `policy:` in your values.

## Health and metrics

The proxy serves three routes on `TELLAGEN_HEALTH_ADDR`:

- `GET /healthz` answers `ok` and never looks at the network, so a Tellagen outage does not restart a pod.
- `GET /readyz` answers 200 when Tellagen answered in the last minute, and 503 otherwise, with JSON that says why.
- `GET /metrics` serves Prometheus metrics: `tellagen_proxy_connected`, `tellagen_proxy_jobs_total`, `tellagen_proxy_job_duration_seconds`, `tellagen_proxy_reconnects_total`, `tellagen_proxy_transport` and `tellagen_proxy_build_info`.

## Verify the image

Releases are signed with [cosign](https://docs.sigstore.dev/cosign/overview/) keyless signing from the release workflow of this repository, and carry an SBOM and build provenance.

```sh
cosign verify ghcr.io/tellagen/tellagen-proxy:<version> \
  --certificate-identity https://github.com/Tellagen/tellagen-proxy/.github/workflows/release.yml@refs/tags/v<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The same command verifies `docker.io/tellagen/tellagen-proxy:<version>` and the chart at `ghcr.io/tellagen/charts/tellagen-proxy:<version>`.

## Documentation

- [Set up Cloud diagnosis](https://tellagen.com/help/set-up-cloud-diagnosis) walks through the setup in Tellagen.
- [The Tellagen guides](https://tellagen.com/help) cover the rest of the product.
- [DESIGN.md](DESIGN.md) describes the architecture, the protocol and the release process.
- [SECURITY.md](SECURITY.md) says how to report a vulnerability.

## Build from source

You need Go 1.26 and, for the image and the chart tests, Docker, Helm, Ruby (the tests use it to read YAML) and Node 22.

```sh
make build        # build the binary
make test         # go test -race ./...
make lint         # golangci-lint
docker build --build-arg VERSION=dev -t tellagen-proxy .
node --test "test/*.test.mjs"
```

## License

[MIT](LICENSE). The image also carries the licenses of its dependencies in `/licenses`.
