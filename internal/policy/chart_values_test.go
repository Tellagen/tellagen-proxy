package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// The Helm chart writes the policy value into a ConfigMap, and the proxy reads
// that file with Load. The policy of the chart's corporate network example must
// pass the strict loader, or a customer who copies it would see the proxy refuse
// to start.
func TestPolicyInTheChartExampleLoads(t *testing.T) {
	values, err := os.ReadFile(filepath.Join("..", "..", "helm", "tellagen-proxy", "ci", "corporate-network.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Policy map[string]any `yaml:"policy"`
	}
	if err := yaml.Unmarshal(values, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Policy) == 0 {
		t.Fatal("the example has no policy")
	}
	rendered, err := yaml.Marshal(document.Policy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := Load(path, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if want := []string{"prom-prod", "loki-prod"}; !reflect.DeepEqual(file.DatasourceUIDs, want) {
		t.Fatalf("DatasourceUIDs = %v, want %v", file.DatasourceUIDs, want)
	}
}
