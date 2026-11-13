# Configuration

The proxy reads its configuration from environment variables and an optional policy file.

Each secret variable `X` can also be set as a file path in `X_FILE`. Set only one of the two. The proxy reads secret files again every minute, so you can rotate a token without a restart. If a value is not usable, the proxy lists every problem and does not start.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TELLAGEN_PROXY_TOKEN` or `_FILE` | required | The proxy token. It starts with `tlg_proxy_`. |
| `GRAFANA_URL` | required | The address the proxy uses to reach Grafana. It never leaves your network. |
| `GRAFANA_SERVICE_ACCOUNT_TOKEN` or `_FILE` | required | A Grafana service account token with the Viewer role. |
| `GRAFANA_PUBLIC_URL` | none | The address people open, for links to Grafana. |
| `GRAFANA_ORG_ID` | none | A Grafana organization id above zero. |
| `GRAFANA_ALLOWED_DATASOURCE_UIDS` | none | A comma-separated list of datasource UIDs. Tellagen can only shorten it. |
| `TELLAGEN_URL` | `https://connect.tellagen.com` | The Tellagen address. It must be `https`, except for `localhost`, loopback addresses and `.localhost` and `.test` names. |
| `TELLAGEN_POLICY_FILE` | none | The path of the [policy file](#policy-file). |
| `TELLAGEN_CA_FILE`, `GRAFANA_CA_FILE` | none | A PEM bundle that adds to the system roots for Tellagen and for Grafana. |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | none | A corporate proxy for traffic to Tellagen. |
| `GRAFANA_HTTPS_PROXY` | none | A proxy for traffic to Grafana. Without it, the proxy reaches Grafana directly. |
| `TELLAGEN_HEALTH_ADDR` | `:8080` | Where the health and metrics endpoint listens. |
| `TELLAGEN_LABELS` | none | Up to 16 labels shown next to the proxy, such as `env=prod,cluster=prod-eu-1`. |
| `TELLAGEN_INSTANCE_ID` | `tellagen-proxy-<hostname>` | The name of this replica. Without a host name, or on `localhost`, it ends in a random suffix. |
| `TELLAGEN_INSTALL_METHOD` | none | How the proxy was installed (`helm`, `docker`, `compose`). Tellagen shows it. |

## Policy file

The policy file is YAML. The proxy does not start on an unknown key or a bad value, so a typo never loosens a limit. You can raise a value up to the ceiling that is built into the binary. A higher value is cut to the ceiling. Only `logs.maxScanBytes` has no ceiling.

| Key | Default | Ceiling | Meaning |
| --- | --- | --- | --- |
| `datasourceUIDs` | none | | The datasources the proxy can query. |
| `capabilities` | all | | The calls the proxy offers. |
| `query.maxTimeout` | `60s` | `60s` | The longest query. |
| `query.maxPerRun` | `40` | `200` | Data queries in one run. |
| `query.maxListPerRun` | `60` | `60` | List and search calls in one run. |
| `query.maxConcurrent` | `2` | `2` | Queries at the same time. |
| `query.maxResultBytes` | `65536` | `65536` | The size of one result. |
| `query.maxItems` | `200` | `200` (`100` for Grafana lookups, `50` for dashboard search) | Items in a list result. |
| `metrics.maxRange` | `24h` | `7d` | The time range of a Prometheus query. |
| `metrics.maxPoints`, `metrics.maxSeries` | `500`, `20` | `500`, `50` | Points and series of a Prometheus query. |
| `logs.maxRange` | `6h` | `24h` | The time range of a Loki query. |
| `logs.maxPoints`, `logs.maxSeries` | `500`, `20` | `500`, `50` | Points and series of a Loki metric query. |
| `logs.maxLines`, `logs.maxLineChars`, `logs.maxPatterns` | `20`, `500`, `5` | `50`, `500`, `5` | Log lines, their length and patterns in a result. |
| `logs.maxScanBytes` | `10737418240` | none | The most data a Loki query can scan. |
| `logs.enforcedMatchers` | none | | Label matchers added to every Loki selector. |
| `redaction.allowOff` | `false` | | Lets a Tellagen admin turn redaction off for this proxy. |
| `redaction.extraRules` | none | | More rules: `{kind: key, key: ...}` or `{kind: pattern, regex: ...}`. |

Tellagen can lower a limit and pick datasources and a number of log lines, but only inside what the file allows. If a request goes above the file, the proxy caps it and says so in its next hello. With Helm, put the same keys under `policy:` in your values.

