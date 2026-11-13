// Command tellagen-proxy connects a customer's Grafana to Tellagen. It polls
// Tellagen over outbound HTTPS, runs typed read-only queries against Grafana, and
// posts back reduced and redacted results. It opens no port except its own health
// endpoint, and it contains no AI.
//
//	tellagen-proxy            run the proxy
//	tellagen-proxy doctor     check the way to Tellagen and Grafana
//	tellagen-proxy version    print the version
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/tellagen/tellagen-proxy/internal/settings"
)

// version is set at build time with -ldflags "-X main.version=1.0.0".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], settings.OSEnvironment(), os.Stdout, os.Stderr))
}

const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2

	usageString = "usage: tellagen-proxy [doctor [--json] | version]\n"
)

func run(args []string, env settings.Environment, stdout, stderr io.Writer) int {
	command := ""
	if len(args) > 0 {
		command = args[0]
	}
	switch command {
	case "":
		return serve(env, stdout, stderr)
	case "doctor":
		return runDoctor(args[1:], env, stdout, stderr)
	case "version", "--version", "-version":
		_, _ = fmt.Fprintln(stdout, "tellagen-proxy", version)
		return exitOK
	case "help", "--help", "-h":
		_, _ = fmt.Fprint(stdout, usageString)
		return exitOK
	}
	_, _ = fmt.Fprintf(stderr, "unknown command %q\n%s", command, usageString)
	return exitUsage
}
