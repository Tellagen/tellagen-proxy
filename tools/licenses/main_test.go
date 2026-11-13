package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	apacheText = "Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/"
	mitText    = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software"
	bsd3Text   = "Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\n* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer.\n* Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products"
	bsd2Text   = "Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\n1. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer."
	iscText    = "Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted"
	mplText    = "Mozilla Public License, version 2.0\n1.12. \"Secondary License\" means either the GNU General Public License, Version 2.0, the GNU Lesser General Public License, Version 2.1, the GNU Affero General Public License, Version 3.0"
	agplText   = "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007"
	gplText    = "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991"
	lgplText   = "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007"
)

func TestIdentify(t *testing.T) {
	cases := map[string]string{
		apacheText:                      "Apache-2.0",
		mitText:                         "MIT",
		bsd3Text:                        "BSD-3-Clause",
		bsd2Text:                        "BSD-2-Clause",
		iscText:                         "ISC",
		mplText:                         "MPL-2.0",
		agplText:                        "AGPL-3.0",
		gplText:                         "GPL",
		lgplText:                        "LGPL",
		"Server Side Public License":    "SSPL-1.0",
		"Do what you want. No warranty": unknownLicense,
		"":                              unknownLicense,
	}
	for text, want := range cases {
		if got := Identify(text); got != want {
			t.Errorf("Identify(%.30q) = %s, want %s", text, got, want)
		}
	}
}

func TestIdentifyIgnoresLineBreaksAndCase(t *testing.T) {
	text := "PERMISSION IS HEREBY GRANTED,\n   FREE OF CHARGE, TO ANY PERSON\nOBTAINING A COPY of this software"
	if got := Identify(text); got != "MIT" {
		t.Fatalf("got %s, want MIT", got)
	}
}

func module(t *testing.T, path string, files map[string]string) Module {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Module{Path: path, Version: "v1.2.3", Dir: dir}
}

func TestCollectKeepsLicenceAndNoticeFilesAndSkipsSource(t *testing.T) {
	mod := module(t, "example.com/apache", map[string]string{
		"LICENSE":    apacheText,
		"NOTICE":     "Copyright Example",
		"license.go": "package x",
		"main.go":    "package x",
	})
	entries, err := Collect([]Module{mod})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(entries[0].Files, ","); got != "LICENSE,NOTICE" {
		t.Fatalf("files = %s", got)
	}
	if got := strings.Join(entries[0].Licenses, ","); got != "Apache-2.0" {
		t.Fatalf("licences = %s", got)
	}
}

func TestCollectReadsEveryLicenceFileOfAModule(t *testing.T) {
	mod := module(t, "example.com/two", map[string]string{"LICENSE": apacheText, "LICENSE.libyaml": mitText})
	entries, err := Collect([]Module{mod})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(entries[0].Licenses, ","); got != "Apache-2.0,MIT" {
		t.Fatalf("licences = %s", got)
	}
}

func TestCollectNamesEveryModuleThatCannotShip(t *testing.T) {
	mods := []Module{
		module(t, "example.com/good", map[string]string{"LICENSE": mitText}),
		module(t, "example.com/none", map[string]string{"main.go": "package x"}),
		module(t, "example.com/noticeonly", map[string]string{"NOTICE": "Copyright"}),
		module(t, "example.com/odd", map[string]string{"LICENSE": "Do what you want"}),
		module(t, "example.com/agpl", map[string]string{"LICENSE": agplText}),
		module(t, "example.com/gpl", map[string]string{"COPYING": gplText}),
		module(t, "example.com/lgpl", map[string]string{"LICENSE": lgplText}),
	}
	_, err := Collect(mods)
	if err == nil {
		t.Fatal("want an error")
	}
	message := err.Error()
	for _, bad := range []string{"none@v1.2.3: no licence file", "noticeonly@v1.2.3: no licence file", "odd@v1.2.3: a licence file is not one", "agpl@v1.2.3: licence AGPL-3.0 must not ship", "gpl@v1.2.3: licence GPL must not ship", "lgpl@v1.2.3: licence LGPL must not ship"} {
		if !strings.Contains(message, bad) {
			t.Errorf("error does not say %q:\n%s", bad, message)
		}
	}
	if strings.Contains(message, "example.com/good") {
		t.Errorf("error names a good module:\n%s", message)
	}
}

func TestWriteCopiesFilesAndWritesTheIndex(t *testing.T) {
	out := filepath.Join(t.TempDir(), "licenses")
	mod := module(t, "example.com/apache/v2", map[string]string{"LICENSE": apacheText, "NOTICE": "Copyright Example"})
	if _, err := Write(out, []Module{mod}); err != nil {
		t.Fatal(err)
	}
	notice, err := os.ReadFile(filepath.Join(out, "example.com", "apache", "v2@v1.2.3", "NOTICE"))
	if err != nil || string(notice) != "Copyright Example" {
		t.Fatalf("NOTICE = %q, %v", notice, err)
	}
	index, err := os.ReadFile(filepath.Join(out, IndexName))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"example.com/apache/v2 v1.2.3", "licence: Apache-2.0", "files: LICENSE, NOTICE"} {
		if !strings.Contains(string(index), want) {
			t.Errorf("index lacks %q:\n%s", want, index)
		}
	}
}

func TestWriteLeavesNothingWhenAModuleIsRefused(t *testing.T) {
	out := filepath.Join(t.TempDir(), "licenses")
	mods := []Module{
		module(t, "example.com/good", map[string]string{"LICENSE": mitText}),
		module(t, "example.com/agpl", map[string]string{"LICENSE": agplText}),
	}
	if _, err := Write(out, mods); err == nil {
		t.Fatal("want an error")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("the output folder exists after a refusal: %v", err)
	}
}

func TestRunReportsAnUnknownPackage(t *testing.T) {
	if err := run(t.TempDir(), "example.invalid/nothing", &strings.Builder{}); err == nil {
		t.Fatal("want an error")
	}
}

// The licenses of the real binary: every module it links carries a license the
// tool knows, none is in the GNU family, and the Apache-2.0 license and the
// NOTICE file of grafana-mcp (when it has one) are in the list.
func TestEveryModuleTheBinaryLinksShipsAnAllowedLicence(t *testing.T) {
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOOS", "linux")
	t.Setenv("GOARCH", "amd64")
	mods, err := ListModules("github.com/tellagen/tellagen-proxy/cmd/tellagen-proxy")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := Collect(mods)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Module.Path, "github.com/tellagen/") {
			t.Errorf("Tellagen's own module %s is in the list", entry.Module.Path)
		}
	}
	var mcp *Entry
	for i := range entries {
		if entries[i].Module.Path == "github.com/grafana/mcp-grafana/v2" {
			mcp = &entries[i]
		}
	}
	if mcp == nil {
		t.Fatal("grafana-mcp is not among the modules the binary links")
	}
	if strings.Join(mcp.Licenses, ",") != "Apache-2.0" || !contains(mcp.Files, "LICENSE") {
		t.Fatalf("grafana-mcp: licences %v, files %v", mcp.Licenses, mcp.Files)
	}
	if _, err := os.Stat(filepath.Join(mcp.Module.Dir, "NOTICE")); err == nil && !contains(mcp.Files, "NOTICE") {
		t.Fatal("grafana-mcp has a NOTICE file and the tool dropped it")
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
