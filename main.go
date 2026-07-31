package main

import (
	"os"

	"github.com/Method-Security/methodazure/cmd"
)

var version = "none"

func main() {
	methodazure := cmd.NewMethodAzure(version)
	methodazure.InitRootCommand()
	methodazure.InitStorageCommand()

	if err := methodazure.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
