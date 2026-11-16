# tellagen-proxy

The proxy lets Tellagen read a Grafana that it cannot reach, for example one in a private network. It connects out to Tellagen over HTTPS, runs read-only queries against your Grafana, and sends back small results with secrets removed.

[Tellagen](https://tellagen.com) uses it for Cloud diagnosis. The AI runs in Tellagen. This proxy is the only part that touches your Grafana.

## What the proxy does

- It only reads. Every request is one of eleven typed read-only calls for Prometheus, Loki and Grafana lookups. The proxy checks each query before it runs. It sends `GET`, or `POST` only to `/api/ds/query`, and follows no redirects.
- It only connects out. The one port it opens (`8080`) serves health checks and metrics.
- You set the limits. A local policy file sets the highest limits. Tellagen can lower them but never raise them. No datasource is queried until an admin picks one in Tellagen.
- It removes secrets. Emails, IP addresses, tokens, keys and card numbers are removed from every result before it leaves your network. If your policy file allows it, a Tellagen admin can turn this off.
- It has no AI model. It runs the Grafana tool code in its own process and starts no MCP server.
- It never prints a token in full. Each request writes one audit line to standard output with the query and the status, and no result data.

[DESIGN.md](DESIGN.md) explains how it works.

## Install

Create a proxy in Tellagen (Settings, Cloud diagnosis) to get the proxy token. Create a Grafana service account with the Viewer role to get a Grafana token. Save them as the files `tellagen-proxy-token` and `grafana-token`. The setup page in Tellagen prints the commands below with your values filled in.

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

Inside the container, `localhost` is the container. If Grafana runs on the Docker host, use `host.docker.internal` or the address of the host.

### Helm

```sh
helm install tellagen-proxy oci://ghcr.io/tellagen/charts/tellagen-proxy \
  --version <version> -n tellagen --create-namespace \
  --set-string grafana.url='https://grafana.example.com' \
  --set-file tellagen.token=./tellagen-proxy-token \
  --set-file grafana.token=./grafana-token
```

You can also add the chart as a repository: `helm repo add tellagen https://charts.tellagen.com`.

Helm keeps these token values in its release record. To keep them out, create the Secret first and point the chart at it:

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

The chart also supports token files from Vault Agent or a CSI driver (`secretFiles.*`). It supports a corporate proxy, a company CA bundle, a policy file, a NetworkPolicy and OpenShift. All values are in [`values.yaml`](helm/tellagen-proxy/values.yaml).

### Read-only access to Kubernetes

The separate `diagnosis-reader` chart installs a read-only role for AI diagnosis and binds it to a group or a service account. It runs no pod. See [its README](helm/diagnosis-reader/README.md).

### Check the connection

```sh
docker exec tellagen-proxy /tellagen-proxy doctor
kubectl -n tellagen exec deploy/tellagen-proxy -- /tellagen-proxy doctor
```

`doctor` checks the variables, DNS, TLS, the path to Tellagen, and Grafana with its datasources. It prints a fix for each problem. If a check fails, it exits with 1. `doctor --json` prints the same report as JSON.

## Variables and limits

Set the proxy with environment variables. Three are required: the proxy token, `GRAFANA_URL` and the Grafana token. A policy file sets the limits. Every variable and policy key is in [docs/configuration.md](docs/configuration.md).

## Health and metrics

The proxy serves three routes on `TELLAGEN_HEALTH_ADDR`.

- `/healthz` answers `ok` and does not check the network.
- When Tellagen answered in the last minute, `/readyz` answers 200. Otherwise it answers 503 and gives the reason as JSON.
- `/metrics` serves Prometheus metrics. Their names start with `tellagen_proxy_`.

## Verify the image

The release workflow of this repository signs each release with [cosign](https://docs.sigstore.dev/cosign/overview/) keyless signing. Each release has an SBOM and build provenance.

```sh
cosign verify ghcr.io/tellagen/tellagen-proxy:<version> \
  --certificate-identity https://github.com/Tellagen/tellagen-proxy/.github/workflows/release.yml@refs/tags/v<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The same command checks the chart at `ghcr.io/tellagen/charts/tellagen-proxy:<version>`.

## Build from source

You need Go 1.26. The image and chart tests also need Docker, Helm, Ruby and Node 22.

```sh
make build        # build the binary
make test         # go test -race ./...
make lint         # golangci-lint
docker build --build-arg VERSION=dev -t tellagen-proxy .
node --test "test/*.test.mjs"
```

## More

[Set up Cloud diagnosis](https://tellagen.com/help/set-up-cloud-diagnosis) walks through the setup in Tellagen. [DESIGN.md](DESIGN.md) covers the architecture, the protocol and the release process. [SECURITY.md](SECURITY.md) says how to report a vulnerability.

## License

[MIT](LICENSE). The image also carries the licenses of its dependencies in `/licenses`.
