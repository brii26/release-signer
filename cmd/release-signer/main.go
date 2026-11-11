package main

import (
	"os"

	"github.com/brii26/release-signer/internal/cli"
)

var version = "dev"

func main() {
	cli.Version = version
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
