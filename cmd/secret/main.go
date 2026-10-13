package main

import (
	"io"
	"os"

	"github.com/avhn/secret/internal/cli"
)

// version is set with -ldflags "-X main.version=<version>" when building a release.
var version = "dev"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	cli.Version = version
	return cli.Main(args, os.Stdin, stdout, stderr)
}
