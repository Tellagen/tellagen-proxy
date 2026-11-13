package main

import (
	"regexp"
	"strings"
)

const unknownLicense = "unknown"

var whitespace = regexp.MustCompile(`\s+`)

// signature names a license by phrases that all appear in its text. The order
// matters: a license whose text names another one comes first. The MPL text
// names the GNU licenses as secondary licenses.
type signature struct {
	id      string
	phrases []string
}

var signatures = []signature{
	{"MPL-2.0", []string{"mozilla public license"}},
	{"Apache-2.0", []string{"apache license", "version 2.0, january 2004"}},
	{"AGPL-3.0", []string{"gnu affero general public license"}},
	{"LGPL", []string{"gnu lesser general public license"}},
	{"GPL", []string{"gnu general public license"}},
	{"SSPL-1.0", []string{"server side public license"}},
	{"BSD-3-Clause", []string{"redistribution and use in source and binary forms", "neither the name"}},
	{"BSD-2-Clause", []string{"redistribution and use in source and binary forms", "this list of conditions and the following disclaimer"}},
	{"ISC", []string{"permission to use, copy, modify, and/or distribute this software for any purpose with or without fee"}},
	{"MIT", []string{"permission is hereby granted, free of charge, to any person obtaining a copy"}},
	{"Unlicense", []string{"this is free and unencumbered software released into the public domain"}},
}

// Identify returns the SPDX name of the license in text, or "unknown".
func Identify(text string) string {
	normal := strings.ToLower(whitespace.ReplaceAllString(text, " "))
	for _, sig := range signatures {
		found := true
		for _, phrase := range sig.phrases {
			if !strings.Contains(normal, phrase) {
				found = false
				break
			}
		}
		if found {
			return sig.id
		}
	}
	return unknownLicense
}

// denied reports whether a license must not ship in the proxy. The GNU family and
// SSPL would extend their terms to the whole program.
func denied(id string) bool {
	return id == "AGPL-3.0" || id == "LGPL" || id == "GPL" || id == "SSPL-1.0"
}
