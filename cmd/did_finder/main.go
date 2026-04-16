package main

import (
	"log"
	"os"

	"github.com/yel-joul/did_finder/internal/runner"
	"github.com/yel-joul/did_finder/internal/tools"
)

func main() {
	options := runner.ParseOptions()

	if options.ToolsRequested() {
		err := tools.PrintCatalog(os.Stdout, tools.ListOptions{
			Category:  options.ToolsCategory,
			Search:    options.ToolsSearch,
			Check:     options.ToolsCheck,
			JSON:      options.ToolsJSON,
			Recommend: options.ToolsRecommend,
			Modules:   options.EnabledToolModules(),
		})
		if err != nil {
			log.Fatalf("Could not print tool catalog: %s", err)
		}
		return
	}

	r, err := runner.NewRunner(options)
	if err != nil {
		log.Fatalf("Could not create runner: %s", err)
	}

	if err := r.Run(); err != nil {
		log.Fatalf("Could not run did_finder: %s\n", err)
	}
}
