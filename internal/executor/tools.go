package executor

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	mcpgrafana "github.com/grafana/mcp-grafana/v2"
	"github.com/grafana/mcp-grafana/v2/tools"
)

// grafanaMCPVersion is the version in this module's go.mod. A test keeps the two
// equal. It goes into the hello and into executed_via.
const grafanaMCPVersion = "v2.2.0"

// allowedTools is every grafana-mcp tool the proxy can reach. The tools are named
// one by one, because a group function would register tools the proxy must not
// have. There is no generic API or SQL tool, and no capability takes a URL.
var allowedTools = map[string]*mcpgrafana.Tool{
	tools.ListDatasources.Tool.Name:           &tools.ListDatasources,
	tools.SearchDashboards.Tool.Name:          &tools.SearchDashboards,
	tools.GetDashboardPanelQueries.Tool.Name:  &tools.GetDashboardPanelQueries,
	tools.ListPrometheusMetricNames.Tool.Name: &tools.ListPrometheusMetricNames,
	tools.ListPrometheusLabelValues.Tool.Name: &tools.ListPrometheusLabelValues,
	tools.QueryPrometheus.Tool.Name:           &tools.QueryPrometheus,
	tools.ListLokiLabelValues.Tool.Name:       &tools.ListLokiLabelValues,
	tools.QueryLokiLogs.Tool.Name:             &tools.QueryLokiLogs,
	tools.QueryLokiPatterns.Tool.Name:         &tools.QueryLokiPatterns,
	tools.AlertRulesRead.Tool.Name:            &tools.AlertRulesRead,
}

//go:embed tools.lock.json
var toolsLockJSON []byte

// toolsLock pins the tools of one grafana-mcp version. Change it only with a
// version bump.
type toolsLock struct {
	Version string            `json:"version"`
	Tools   map[string]string `json:"tools"`
}

func loadToolsLock() (toolsLock, error) {
	var lock toolsLock
	if err := json.Unmarshal(toolsLockJSON, &lock); err != nil {
		return toolsLock{}, fmt.Errorf("read the tool lock file: %w", err)
	}
	return lock, nil
}

func schemaDigest(tool *mcpgrafana.Tool) (string, error) {
	encoded, err := json.Marshal(tool.Tool.InputSchema)
	if err != nil {
		return "", fmt.Errorf("encode the schema of %s: %w", tool.Tool.Name, err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// verifyTools compares the tools with the lock file and returns every difference.
// The proxy refuses to start on any, because a changed tool could read more than
// was reviewed.
func verifyTools(registered map[string]*mcpgrafana.Tool, lock toolsLock, version string) error {
	var problems []string
	if lock.Version != version {
		problems = append(problems, fmt.Sprintf("the lock file is for grafana-mcp %s, and this build has %s", lock.Version, version))
	}
	for _, name := range slices.Sorted(maps.Keys(lock.Tools)) {
		if _, ok := registered[name]; !ok {
			problems = append(problems, fmt.Sprintf("tool %s is in the lock file but not registered", name))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(registered)) {
		tool := registered[name]
		want, ok := lock.Tools[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("tool %s is registered but not in the lock file", name))
			continue
		}
		if tool.Tool.Name != name {
			problems = append(problems, fmt.Sprintf("tool %s now calls itself %s", name, tool.Tool.Name))
		}
		got, err := schemaDigest(tool)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if got != want {
			problems = append(problems, fmt.Sprintf("tool %s has a changed input schema: %s, locked %s", name, got, want))
		}
		annotations := tool.Tool.Annotations
		if annotations == nil || !annotations.ReadOnlyHint || annotations.DestructiveHint == nil || *annotations.DestructiveHint {
			problems = append(problems, fmt.Sprintf("tool %s is not marked as read-only and not destructive", name))
		}
	}
	if len(problems) > 0 {
		return errors.New("the grafana-mcp tool list changed: " + strings.Join(problems, "; "))
	}
	return nil
}
