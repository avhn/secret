package main

import (
	"fmt"
	"io"
	"os"
)

// version is set with -ldflags "-X main.version=<version>" when building a release.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Fprintf(stdout, "secret %s (go)\n", version)
		return 0
	}

	fmt.Fprintln(stderr, "not yet implemented in the Go build; use bin/secret")
	return 2
}
