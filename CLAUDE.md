# CLAUDE.md

Guidance for coding agents that work in this repository. Read [DESIGN.md](DESIGN.md) before you change how a command runs, and [README.md](README.md) for the settings.

## What this repository is

`tellagen-proxy` is a small Go service that runs in a customer's network. It polls Tellagen over outbound HTTPS, runs read-only queries against the customer's Grafana, and sends back reduced, redacted results. It is a public repository: everything you write here is public.

## Layout

```text
cmd/tellagen-proxy/   the command line and the wiring
protocol/             public package: wire types, token, capabilities, results
redact/               public package: redaction rules
internal/             agent, executor, policy, guard, reduce, settings, hub, grafana, doctor
tools/licenses/       collects license text for the image
helm/tellagen-proxy/  the Helm chart
scripts/, test/       Node scripts and tests for the chart, the image and the release
.github/workflows/    ci.yml and release.yml
```

`protocol` and `redact` are imported by Tellagen itself. Treat their exported API and their JSON as a contract: do not rename a field or change a message without a new protocol version. The golden files in `protocol/testdata` pin the JSON.

## Commands

```sh
make build        # build the binary
make test         # go test -race ./...
make lint         # golangci-lint
make fmt          # gofmt
make vet          # go vet
make tidy         # go mod tidy
make integration  # tests that need Docker (build tag integration)
make docker       # build the image
node --test "test/*.test.mjs"   # chart, image-check and workflow tests (Node 22)
```

The chart tests need `helm` and `ruby` on `PATH` and skip with a message when one is missing. After you change the chart, refresh the snapshots with `UPDATE_SNAPSHOTS=1 node --test test/chart.test.mjs` and read the diff.

Run the checks of the package you changed first, then `make test` and `make lint` before you hand work back.

## Code style

- Keep the code lean. Small functions, early returns, clear names. No dead code, no commented-out code, no TODO text, no abstraction for a case that does not exist.
- Comments say why, never what. A package comment is one or two lines. An exported identifier has a one-line doc comment that starts with its name. Keep a longer comment only where a reader could get a security or protocol detail wrong.
- No ticket keys, sprint names, people names or private repository names in code, comments, commits or docs. Use American English and plain words.
- Wrap errors with `%w`. Error messages are lowercase and have no final period. Library code never panics. Pass `context.Context` first.
- Format with `gofmt`. The linters are errcheck, govet, ineffassign, staticcheck (SA checks) and unused, in `.golangci.yml`.

## Testing

- Write table tests. Cover the failure path as well as the happy path.
- Do not delete a test to make a build pass. If a test is wrong, change it and say why.
- A change to a message in `protocol` or a rule in `redact` or `internal/guard` needs a test that fails without the change.
- Tests use no network and no real Grafana. A test that needs Docker has the `integration` build tag.

## Security rules

- Never log, print or return a token. Use `protocol.TokenHint` when you must show one. Secrets stay in `settings.Secret`, which reads them on demand.
- The proxy only reads. Do not add a tool, a capability or an HTTP method that writes. The tool list in `internal/executor/tools.go` is explicit and pinned by `tools.lock.json`: a new tool needs a review of its schema and an update to the lock file together.
- The policy is deny by default for data. With no update from Tellagen, `policy.NewEngine` allows no datasource, turns log lines off and keeps redaction on. A policy file sets the highest limits, up to the ceilings built into the binary (`logs.maxScanBytes` has none). Tellagen can lower them and choose datasources, log lines and redaction, but only inside the file: a request above the file is capped and reported in the next hello. Never write code that lets a request raise a limit.
- A query the guard cannot parse is refused. Do not turn a parse failure into a pass.
- Redaction runs before any cut, so a secret is never cut in half before it is seen. Keep that order.
- The proxy opens no listener except the health endpoint, and it never accepts a request that Tellagen started.
- Workflow files pin every action to a commit SHA and ask for the least permission. `test/workflows.test.mjs` checks this.

## Release rules

- Agents never create a tag, a release or a registry push, and never run the release workflow. A person tags `v*` on a commit on `master`.
- Do not edit `Chart.yaml` versions: they stay `0.0.0` and the release workflow sets them.
- Add a line to the Unreleased section of `CHANGELOG.md` for any change a user would notice. The release notes come from it.

## Public repository rules

- Do not commit a secret, a real token, a customer name or an internal address. Test values use `example.com`, `tlg_proxy_test.token` and similar fakes.
- Do not copy text or code from private sources into this repository.
- Commit messages start with `fix:`, `feat:`, `test:`, `docs:`, `ci:` or `chore:` and say what changed and why. Do not stage, commit or push unless the person asks you to.
