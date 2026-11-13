package doctor

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/tellagen/tellagen-proxy/internal/grafana"
)

// grafana checks the way to Grafana and the token: reachable, accepted, the right
// org, a role that is not too broad, and a datasource that answers.
func (r *runner) grafana(ctx context.Context) {
	s := r.Settings
	transport, err := s.GrafanaTransport()
	if err != nil {
		r.fail("grafana", "ca_file", err.Error(), "Fix: point GRAFANA_CA_FILE at a PEM file with the CA that signed the Grafana certificate")
		return
	}
	defer transport.CloseIdleConnections()
	transport.DialContext = r.Net.DialContext
	client := grafana.New(grafana.Config{BaseURL: s.GrafanaURL, Transport: transport, Token: s.GrafanaToken.Value, OrgID: s.GrafanaOrgID})

	health, err := client.Health(ctx)
	if err != nil {
		r.grafanaFailure(err)
		return
	}
	identity, err := client.Identity(ctx)
	if err != nil {
		r.grafanaFailure(err)
		return
	}
	if s.GrafanaOrgID > 0 && identity.OrgID != s.GrafanaOrgID {
		r.fail("grafana", "grafana_wrong_org",
			fmt.Sprintf("the token belongs to org %d (%s), but GRAFANA_ORG_ID is %d", identity.OrgID, identity.OrgName, s.GrafanaOrgID),
			fmt.Sprintf("Fix: create the service account in org %d, or change GRAFANA_ORG_ID", s.GrafanaOrgID))
		return
	}
	role := identity.Role
	if role == "" {
		role = "unknown"
	}
	version := ""
	if health.Version != "" {
		version = " v" + health.Version + ","
	}
	r.report.add("grafana", OK, "", fmt.Sprintf("%s%s org %d, role %s", client.Describe(), version, identity.OrgID, role))
	r.report.grafanaRole = identity.Role
	r.report.grafanaLatencyMS = int(health.Latency.Milliseconds())

	datasources, listErr := client.Datasources(ctx)
	r.role(identity.Role, datasources, listErr)
	if !r.Short && listErr == nil {
		r.smoke(ctx, client, datasources)
	}
}

// grafanaFailure explains a failed Grafana call.
func (r *runner) grafanaFailure(err error) {
	failure := grafana.Explain(err)
	if r.localhostInContainer(failure) {
		r.fail("grafana", "grafana_localhost", "GRAFANA_URL points to localhost, which inside a container is the container itself",
			"Fix: with Docker use host.docker.internal or --network host. In Kubernetes use the Grafana service name,",
			"such as http://grafana.monitoring.svc:3000")
		return
	}
	var more []string
	switch failure.Code {
	case grafana.CodeUnauthorized, grafana.CodeForbidden:
		more = []string{"Fix: create a new service account token in Grafana (an expired token fails this way)", "and update " + r.Settings.GrafanaToken.Source()}
	case grafana.CodeUnknownCA, grafana.CodeCertificate:
		more = []string{"Fix: set GRAFANA_CA_FILE to the CA that signed the Grafana certificate"}
	case grafana.CodeDNS:
		more = []string{"Fix: check GRAFANA_URL, and that this host or container can resolve the name"}
	case grafana.CodeRefused:
		more = []string{"Fix: check the host and port in GRAFANA_URL. Grafana must listen where the proxy can reach it"}
	case grafana.CodeTimeout:
		more = []string{"Fix: a firewall may block the way to Grafana. If Grafana needs a proxy, set GRAFANA_HTTPS_PROXY"}
	case grafana.CodeHTTP:
		more = []string{"Fix: check that GRAFANA_URL points at Grafana and not at a login page or another service"}
	default:
		more = []string{"Fix: check GRAFANA_URL, and that this host can reach it"}
	}
	r.failPublic("grafana", failure.Code, failure.Message+".", failure.Message+" ("+r.Settings.GrafanaURL.Host+")", more...)
}

func (r *runner) localhostInContainer(failure grafana.Failure) bool {
	if failure.Auth || failure.Code == grafana.CodeUnknownCA || failure.Code == grafana.CodeHTTP {
		return false
	}
	host := r.Settings.GrafanaURL.Hostname()
	local := host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
	return local && r.Net.InContainer != nil && r.Net.InContainer()
}

// role warns about a token that can do more than it must, or that cannot be
// limited to the datasources Tellagen may read.
func (r *runner) role(role string, datasources []grafana.Datasource, listErr error) {
	switch role {
	case "Admin", "Editor":
		r.report.add("grafana", Warn, "role_too_broad", fmt.Sprintf("the token has the %s role, which can change Grafana. Tellagen only reads", role),
			"Use a service account with the Viewer role")
	case "Viewer":
		if r.allowlisted() || listErr != nil || len(datasources) == 0 {
			return
		}
		r.report.add("grafana", Warn, "viewer_all_datasources", fmt.Sprintf("Viewer can query all %d datasources in this org.", len(datasources)),
			"Consider GRAFANA_ALLOWED_DATASOURCE_UIDS")
	}
}

func (r *runner) allowlisted() bool {
	return r.Settings.AllowedDatasourceUIDs != nil || (r.policy != nil && r.policy.DatasourceUIDs != nil)
}

// smoke runs the cheapest query on the first Prometheus and the first Loki
// datasource that the proxy may use.
func (r *runner) smoke(ctx context.Context, client *grafana.Client, datasources []grafana.Datasource) {
	var outcomes, failures []string
	for _, kind := range []string{"prometheus", "loki"} {
		index := slices.IndexFunc(datasources, func(d grafana.Datasource) bool {
			return d.Type == kind && r.mayUse(d.UID)
		})
		if index < 0 {
			continue
		}
		datasource := datasources[index]
		query, latency, err := client.Smoke(ctx, datasource)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %s (%s)", datasource.UID, query, grafana.Explain(err).Message))
			continue
		}
		outcomes = append(outcomes, fmt.Sprintf("%s: %s %d ms", datasource.UID, query, latency.Milliseconds()))
	}
	if len(outcomes) > 0 {
		r.report.add("grafana", OK, "", strings.Join(outcomes, ", "))
	}
	for _, failure := range failures {
		r.report.add("grafana", Warn, "datasource_query_failed", "a test query failed on "+failure, "Check the datasource in Grafana")
	}
}

func (r *runner) mayUse(uid string) bool {
	if allowed := r.Settings.AllowedDatasourceUIDs; allowed != nil && !slices.Contains(allowed, uid) {
		return false
	}
	return r.policy == nil || r.policy.DatasourceUIDs == nil || slices.Contains(r.policy.DatasourceUIDs, uid)
}
