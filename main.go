package main

import (
	"os"

	"github.com/alphasoc/alphasocbeat/cmd"

	_ "github.com/alphasoc/alphasocbeat/include"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
