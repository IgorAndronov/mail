package main

import (
	"flag"
	"log"

	"github.com/yourusername/emailserver/internal/app"
)

func main() {
	// Parse command line flags
	configFile := flag.String("config", "", "Path to config file")
	flag.Parse()

	// Create and run application
	app, err := app.New(*configFile)
	if err != nil {
		log.Fatalf("Failed to initialize application: %v\n", err)
	}

	if err := app.Run(); err != nil {
		log.Fatalf("Application error: %v\n", err)
	}
}
