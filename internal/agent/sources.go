package agent

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"time"

	"github.com/tellagen/tellagen-proxy/internal/grafana"
	"github.com/tellagen/tellagen-proxy/protocol"
)

// publicURLLookupTimeout bounds the lookup of the public address in a hello.
const publicURLLookupTimeout = 3 * time.Second

// sharedAddressSpace is RFC 6598, which VPN overlays such as Tailscale use.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// checkGrafana asks Grafana for its health and datasources and keeps the answer.
// The messages it keeps name no address: that stays inside the customer network.
func (a *Agent) checkGrafana(ctx context.Context) {
	snapshot := grafanaSnapshot{checkedAt: a.now(), health: protocol.HealthOK}
	health, err := a.cfg.Grafana.Health(ctx)
	snapshot.version = health.Version
	if err == nil {
		snapshot.datasources, err = a.cfg.Grafana.Datasources(ctx)
	}
	if err != nil {
		failure := grafana.Explain(err)
		snapshot.health, snapshot.code, snapshot.message = protocol.HealthUnavailable, protocol.CodeSourceUnavailable, failure.Message
		if failure.Auth {
			snapshot.code = protocol.CodeAuthFailed
		}
		snapshot.datasources = nil
	}
	a.mu.Lock()
	a.grafana = snapshot
	a.mu.Unlock()
}

// watchGrafana repeats the check, so that polls report a Grafana that went down
// or lost its token. It never touches the probes: that must not restart the pod.
func (a *Agent) watchGrafana(ctx context.Context) {
	for {
		timer := time.NewTimer(a.jitter(a.cfg.GrafanaCheckEvery))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			a.checkGrafana(ctx)
		}
	}
}

// sources builds the hello's list of Grafana sources from a fresh check. When the
// policy file names datasources, only those are listed.
func (a *Agent) sources(ctx context.Context, allowed []string) []protocol.Source {
	a.checkGrafana(ctx)
	a.mu.Lock()
	snapshot := a.grafana
	a.mu.Unlock()

	source := protocol.Source{
		Key:              sourceKey,
		PublicURL:        a.cfg.PublicURL,
		PublicURLNetwork: a.publicURLNetwork(ctx),
		GrafanaVersion:   snapshot.version,
		Health:           snapshot.health,
		Datasources:      []protocol.SourceDatasource{},
	}
	for _, datasource := range snapshot.datasources {
		if allowed != nil && !slices.Contains(allowed, datasource.UID) {
			continue
		}
		source.Datasources = append(source.Datasources, protocol.SourceDatasource{UID: datasource.UID, Name: datasource.Name, Type: datasource.Type, Default: datasource.Default})
	}
	return []protocol.Source{source}
}

// publicURLNetwork says whether the address people open answers only with private
// addresses here. A failed lookup says nothing: no report is better than a wrong one.
func (a *Agent) publicURLNetwork(ctx context.Context) string {
	if a.cfg.PublicURL == "" {
		return ""
	}
	parsed, err := url.Parse(a.cfg.PublicURL)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	lookup := a.cfg.LookupIP
	if lookup == nil {
		lookup = lookupIP
	}
	lookupCtx, cancel := context.WithTimeout(ctx, publicURLLookupTimeout)
	defer cancel()
	addresses, err := lookup(lookupCtx, parsed.Hostname())
	if err != nil || len(addresses) == 0 {
		return ""
	}
	for _, address := range addresses {
		if !isPrivateAddress(address) {
			return ""
		}
	}
	return protocol.NetworkPrivate
}

func lookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func isPrivateAddress(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || sharedAddressSpace.Contains(address)
}

// sourcesHealth is the cached check, for the poll.
func (a *Agent) sourcesHealth() []protocol.SourceHealth {
	a.mu.Lock()
	snapshot := a.grafana
	a.mu.Unlock()
	if snapshot.checkedAt.IsZero() {
		return nil
	}
	checkedAt := snapshot.checkedAt.UTC().Truncate(time.Second)
	return []protocol.SourceHealth{{Key: sourceKey, Health: snapshot.health, Code: snapshot.code, Message: snapshot.message, CheckedAt: &checkedAt}}
}
