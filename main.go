package main

import (
	"github.com/svector-corporation/orbit-cli/cmd"
	"github.com/svector-corporation/orbit-cli/internal/logging"
)

func main() {
	defer logging.RecoverPanic("main", func() {
		logging.ErrorPersist("Application terminated due to unhandled panic")
	})

	cmd.Execute()
}
