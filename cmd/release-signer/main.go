package main

import (
	"fmt"
	"os"
)

var version = "dev"

const usage = `release-signer: sign and verify software releases

Usage:
  release-signer <command> [flags]

Flags:
  --help      show this help
  --version   show program version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "--help", "-h":
		fmt.Print(usage)
	case "--version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}
