# Security policy

## Report a vulnerability

Email hello@tellagen.com with the subject "Security report". Do not open a public issue for a vulnerability.

Tell us which version you use, what you found, and the steps to repeat it. We reply as soon as we can.

## Supported versions

We fix security problems in the latest release of `tellagen-proxy`. Update to the latest version before you report.

## What the proxy does with your data

The proxy runs in your network. It opens outbound HTTPS connections to Tellagen and to your Grafana, and it listens on one port, for health checks and metrics.

- It sends the proxy token only to the Tellagen address you set in `TELLAGEN_URL` (the default is `https://connect.tellagen.com`) and the Grafana service account token only to `GRAFANA_URL`.
- It runs read-only queries. Every query passes a guard and your local policy file before it reaches Grafana, and the result is reduced and redacted before it leaves your network.
- It never writes a token to a log, a metric or a result. `doctor` prints only a short hint of the proxy token: its start and its last four characters.

How this works is in [DESIGN.md](DESIGN.md). You can verify a release image with the steps in [README.md](README.md#verify-the-image).
