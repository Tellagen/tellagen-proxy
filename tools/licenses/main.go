// Command licenses writes the license text of every module that a Go package
// links in, so that the image can ship it. It fails when a module has no license
// file, when a license is not one it knows, or when a license is one the proxy
// must not carry (the GNU family and SSPL).
//
//	GOOS=linux GOARCH=arm64 licenses -out /licenses .
//
// The directory holds one folder per module, named module@version, with every
// LICENSE, COPYING, NOTICE and PATENTS file from the module root, and an index
// named THIRD-PARTY.txt.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// IndexName is the file that lists every module and its license.
const IndexName = "THIRD-PARTY.txt"

func main() {
	out := flag.String("out", "", "directory to write the license files to")
	flag.Parse()
	if *out == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: licenses -out DIR PACKAGE")
		os.Exit(2)
	}
	if err := run(*out, flag.Arg(0), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "licenses:", err)
		os.Exit(1)
	}
}

func run(out, pkg string, stdout io.Writer) error {
	mods, err := ListModules(pkg)
	if err != nil {
		return err
	}
	goroot, err := goEnv("GOROOT")
	if err != nil {
		return err
	}
	version, err := goEnv("GOVERSION")
	if err != nil {
		return err
	}
	mods = append(mods, Module{Path: "go", Version: version, Dir: goroot})
	entries, err := Write(out, mods)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "wrote the licences of %d modules to %s\n", len(entries), out)
	return nil
}

// Module is one module that the binary links in.
type Module struct {
	Path    string
	Version string
	Dir     string
}

// Entry is a module with the license files found for it.
type Entry struct {
	Module   Module
	Files    []string
	Licenses []string
}

// ListModules returns the modules that provide the packages the binary links,
// without the main module and without modules replaced by a local directory. It
// reads the build target from the environment, as go build does.
func ListModules(pkg string) ([]Module, error) {
	format := `{{if not .Standard}}{{with .Module}}{{if not .Main}}{{if or (not .Replace) .Replace.Version}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}{{end}}{{end}}{{end}}`
	cmd := exec.Command("go", "list", "-deps", "-f", format, pkg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go list: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	seen := map[string]bool{}
	var mods []Module
	for _, line := range strings.Split(stdout.String(), "\n") {
		parts := strings.Split(strings.TrimSpace(line), "|")
		if len(parts) != 3 || seen[parts[0]] {
			continue
		}
		seen[parts[0]] = true
		mods = append(mods, Module{Path: parts[0], Version: parts[1], Dir: parts[2]})
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })
	return mods, nil
}

func goEnv(name string) (string, error) {
	output, err := exec.Command("go", "env", name).Output()
	if err != nil {
		return "", fmt.Errorf("go env %s: %w", name, err)
	}
	return strings.TrimSpace(string(output)), nil
}

// Write copies the license files of mods into out and writes the index. It
// returns an error that lists every module it could not accept, and then writes
// nothing.
func Write(out string, mods []Module) ([]Entry, error) {
	entries, err := Collect(mods)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		folder := filepath.Join(out, filepath.FromSlash(entry.Module.Path)+"@"+entry.Module.Version)
		if err := os.MkdirAll(folder, 0o755); err != nil {
			return nil, err
		}
		for _, name := range entry.Files {
			data, err := os.ReadFile(filepath.Join(entry.Module.Dir, name))
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(folder, name), data, 0o644); err != nil {
				return nil, err
			}
		}
	}
	if err := os.WriteFile(filepath.Join(out, IndexName), Index(entries), 0o644); err != nil {
		return nil, err
	}
	return entries, nil
}

// Collect finds the license files of mods and names their licenses.
func Collect(mods []Module) ([]Entry, error) {
	var entries []Entry
	var problems []string
	for _, mod := range mods {
		entry, err := inspect(mod)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		entries = append(entries, entry)
	}
	if len(problems) > 0 {
		return nil, errors.New("these modules cannot ship in the image:\n  " + strings.Join(problems, "\n  "))
	}
	return entries, nil
}

func inspect(mod Module) (Entry, error) {
	label := mod.Path + "@" + mod.Version
	listing, err := os.ReadDir(mod.Dir)
	if err != nil {
		return Entry{}, fmt.Errorf("%s: %w", label, err)
	}
	entry := Entry{Module: mod}
	for _, item := range listing {
		if item.IsDir() || !isLicenseFile(item.Name()) {
			continue
		}
		entry.Files = append(entry.Files, item.Name())
		if !isNoticeFile(item.Name()) {
			data, err := os.ReadFile(filepath.Join(mod.Dir, item.Name()))
			if err != nil {
				return Entry{}, fmt.Errorf("%s: %w", label, err)
			}
			entry.Licenses = append(entry.Licenses, Identify(string(data)))
		}
	}
	if len(entry.Licenses) == 0 {
		return Entry{}, fmt.Errorf("%s: no licence file in the module root", label)
	}
	for _, id := range entry.Licenses {
		switch {
		case id == unknownLicense:
			return Entry{}, fmt.Errorf("%s: a licence file is not one this tool knows. Read it, then teach the tool", label)
		case denied(id):
			return Entry{}, fmt.Errorf("%s: licence %s must not ship in the proxy", label, id)
		}
	}
	entry.Licenses = unique(entry.Licenses)
	return entry, nil
}

// isLicenseFile matches LICENSE, LICENCE, COPYING, NOTICE, UNLICENSE and PATENTS
// files with any extension, and not Go source such as license.go.
func isLicenseFile(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".go") {
		return false
	}
	for _, prefix := range []string{"license", "licence", "copying", "notice", "unlicense", "patents"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// isNoticeFile is true for files that carry attribution or a patent grant and
// are not a license by themselves.
func isNoticeFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "notice") || strings.HasPrefix(lower, "patents")
}

func unique(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

// Index renders THIRD-PARTY.txt: one line per module with its licenses and files.
func Index(entries []Entry) []byte {
	var b bytes.Buffer
	b.WriteString("Third-party software in tellagen-proxy\n")
	b.WriteString("Each folder next to this file holds the licence text of one module.\n\n")
	for _, entry := range entries {
		fmt.Fprintf(&b, "%s %s\n  licence: %s\n  files: %s\n", entry.Module.Path, entry.Module.Version, strings.Join(entry.Licenses, ", "), strings.Join(entry.Files, ", "))
	}
	return b.Bytes()
}
