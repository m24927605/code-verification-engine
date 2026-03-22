package main

import (
	"os"

	"github.com/verabase/code-verification-engine/internal/cli"
)

func main() {
	exitCode := cli.Run(os.Args[1:])
	os.Exit(exitCode)
}
