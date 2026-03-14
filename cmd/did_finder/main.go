package main

import (
	"log"

	"github.com/yel-joul/did_finder/internal/runner"
)

func main() {
	options := runner.ParseOptions()
	
	r, err := runner.NewRunner(options)
	if err != nil {
		log.Fatalf("Could not create runner: %s", err)
	}

	if err := r.Run(); err != nil {
		log.Fatalf("Could not run did_finder: %s\n", err)
	}
}
