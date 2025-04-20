package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/viper"

	"github.com/yourusername/emailserver/internal/api"
	"github.com/yourusername/emailserver/internal/app"
)

func main() {
	var cfgFile *string = flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()
	if *cfgFile != "" {
		viper.SetConfigFile(*cfgFile)
	}

	/* ---------- core ---------- */
	a := &app.App{}
	if err := a.Init(); err != nil {
		log.Fatalf("init: %v", err)
	}

	/* ---------- HTTP layer ---------- */
	router := api.SetupRouter(a)
	a.SetWebRouter(router)

	// start HTTP server in its own goroutine
	addr := fmt.Sprintf("%s:%d", a.GetConfig().WebHost, a.GetConfig().WebPort)
	go func() {
		if err := router.Run(addr); err != nil {
			log.Fatalf("http: %v", err)
		}
	}()

	// start SMTP server (inside a.Run)
	go a.Run()

	/* ---------- graceful shutdown ---------- */
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutdown")

	_ = a.Close()
}
