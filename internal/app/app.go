package app

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/yourusername/emailserver/internal/api"
	"github.com/yourusername/emailserver/internal/auth"
	"github.com/yourusername/emailserver/internal/config"
	"github.com/yourusername/emailserver/internal/email"
	"github.com/yourusername/emailserver/internal/storage"
)

// App represents the main application
type App struct {
	cfg             config.Config
	db              *storage.Database
	fileStorage     *storage.FileStorage
	authService     *auth.Service
	smtpServer      *email.SMTPServer
	outboundService *email.OutboundService
	httpServer      *http.Server
}

// New creates a new application instance
func New(configFile string) (*App, error) {
	// Load configuration
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return nil, err
	}

	// Initialize database
	db, err := storage.NewDatabase(cfg.DB)
	if err != nil {
		return nil, err
	}

	// Initialize file storage
	fileStorage, err := storage.NewFileStorage(cfg.EmailStoragePath)
	if err != nil {
		return nil, err
	}

	// Initialize authentication service
	authService := auth.NewService(cfg.JWTSecret)

	// Initialize outbound email service
	outboundService := email.NewOutboundService(cfg, cfg.OwnDomains)

	// Initialize SMTP server
	smtpServer := email.NewSMTPServer(cfg, db, fileStorage, outboundService)

	// Initialize API handlers and middleware
	handler := api.NewHandler(db, fileStorage, authService, outboundService, cfg.Domain)
	middleware := api.NewMiddleware(authService)

	// Set up router
	router := api.SetupRouter(handler, middleware)

	// Initialize HTTP server
	httpServer := &http.Server{
		Addr:    cfg.WebHost + ":" + strconv.Itoa(cfg.WebPort),
		Handler: router,
	}

	return &App{
		cfg:             cfg,
		db:              db,
		fileStorage:     fileStorage,
		authService:     authService,
		smtpServer:      smtpServer,
		outboundService: outboundService,
		httpServer:      httpServer,
	}, nil
}

// Run starts the application
func (a *App) Run() error {
	// Start SMTP server in a goroutine
	go func() {
		if err := a.smtpServer.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("SMTP server error: %v\n", err)
		}
	}()

	// Start HTTP server in a goroutine
	go func() {
		if err := a.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shut down the servers
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down servers...")

	// Create a deadline for server shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := a.httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP server forced to shutdown: %v\n", err)
	}

	// Close SMTP server
	if err := a.smtpServer.Close(); err != nil {
		log.Printf("SMTP server forced to shutdown: %v\n", err)
	}

	// Close database connection
	if err := a.db.Close(); err != nil {
		log.Printf("Error closing database connection: %v\n", err)
	}

	log.Println("Servers stopped")
	return nil
}
