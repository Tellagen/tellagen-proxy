package executor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// moduleRoot is the repository root, seen from this package.
const moduleRoot = "../.."

func listDeps(t *testing.T) []string {
	t.Helper()
	command := exec.Command("go", "list", "-deps", "./...")
	command.Dir = moduleRoot
	output, err := command.Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	return strings.Fields(string(output))
}

// TestBinaryLinksNoAGPLLoki walks what the compiler links for every package of the
// module, so it also covers a package that nothing imports yet.
func TestBinaryLinksNoAGPLLoki(t *testing.T) {
	deps := listDeps(t)
	if len(deps) < 100 {
		t.Fatalf("go list found only %d packages", len(deps))
	}
	banned := []string{"github.com/grafana/loki"}
	for _, dep := range deps {
		for _, prefix := range banned {
			if dep == prefix || strings.HasPrefix(dep, prefix+"/") {
				t.Errorf("the proxy links %s", dep)
			}
		}
	}
}

// TestExecutorStartsNoServer keeps the second read-only layer a property of the
// source: this package registers no tool group, builds no MCP server and opens no
// listener. Tool variables are named one by one in allowedTools.
func TestExecutorStartsNoServer(t *testing.T) {
	banned := map[string]bool{
		"NewServer": true, "ListenAndServe": true, "ListenAndServeTLS": true, "Listen": true,
		"AddAPITools": true, "AddSQLTools": true, "Register": true,
	}
	addGroup := regexp.MustCompile(`^Add[A-Z].*Tools$`)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if ok && (banned[selector.Sel.Name] || addGroup.MatchString(selector.Sel.Name)) {
				t.Errorf("%s calls %s", fset.Position(selector.Pos()), selector.Sel.Name)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no source file was read")
	}
}

// TestLockVersionMatchesGoMod keeps grafanaMCPVersion, which the hello reports, the
// same as what the build links.
func TestLockVersionMatchesGoMod(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(moduleRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "github.com/grafana/mcp-grafana/v2 "+grafanaMCPVersion) {
		t.Errorf("go.mod does not require grafana-mcp %s", grafanaMCPVersion)
	}
}
