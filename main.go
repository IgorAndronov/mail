package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

// Config structure for application configuration
type Config struct {
	SMTPHost         string
	SMTPPort         int
	WebHost          string
	WebPort          int
	Domain           string
	DB               DBConfig
	TrustedDomains   []string
	JWTSecret        string
	CertFile         string
	KeyFile          string
	EmailStoragePath string
}

// DBConfig for database connection
type DBConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// User represents a mail server user
type User struct {
	ID             string    `db:"id" json:"id"`
	Email          string    `db:"email" json:"email"`
	PasswordHash   string    `db:"password_hash" json:"-"`
	IsActive       bool      `db:"is_active" json:"is_active"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time `db:"updated_at" json:"updated_at"`
	IsAdmin        bool      `db:"is_admin" json:"is_admin"`
	ExternalDomain bool      `db:"external_domain" json:"external_domain"`
}

// Mailbox represents a mailbox owned by a user
type Mailbox struct {
	ID        string    `db:"id" json:"id"`
	Address   string    `db:"address" json:"address"`
	UserID    string    `db:"user_id" json:"user_id"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// Email represents an email message
type Email struct {
	ID        string     `db:"id" json:"id"`
	From      string     `db:"from_address" json:"from"`
	To        string     `db:"to_address" json:"to"`
	Subject   string     `db:"subject" json:"subject"`
	Body      string     `db:"body" json:"body"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
	ReadAt    *time.Time `db:"read_at" json:"read_at"`
	MailboxID string     `db:"mailbox_id" json:"mailbox_id"`
}

// PermissionRequest represents a request to send emails
type PermissionRequest struct {
	ID             string     `db:"id" json:"id"`
	RequestorEmail string     `db:"requestor_email" json:"requestor_email"`
	TargetMailbox  string     `db:"target_mailbox" json:"target_mailbox"`
	Token          string     `db:"token" json:"token"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
	ApprovedAt     *time.Time `db:"approved_at" json:"approved_at"`
	ExpiresAt      time.Time  `db:"expires_at" json:"expires_at"`
}

// UserLogin is used for login requests
type UserLogin struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// UserRegistration is used for registration requests
type UserRegistration struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// MailboxCreation is used for creating new mailboxes
type MailboxCreation struct {
	Address string `json:"address" binding:"required"`
}

// PermissionRequestCreation for requesting permission to send emails
type PermissionRequestCreation struct {
	TargetMailbox string `json:"target_mailbox" binding:"required"`
}

// App is the main application struct
type App struct {
	config         Config
	db             *sqlx.DB
	smtpServer     *smtp.Server
	smtpBackend    *Backend
	webRouter      *gin.Engine
	allowedSenders map[string]map[string]bool // Map of target address -> allowed sender emails
}

// Backend implements SMTP server backend
type Backend struct {
	app *App
}

// Session implements SMTP server session
type Session struct {
	app         *App
	from        string
	to          []string
	data        []byte
	currentSize int
}

// Init initializes the application
func (a *App) Init() error {
	log.Println("Initializing application...")

	// Load configuration
	if err := a.loadConfig(); err != nil {
		return err
	}

	// Connect to database
	if err := a.connectDB(); err != nil {
		return err
	}

	// Initialize SMTP backend and server
	a.initSMTP()

	// Initialize web server
	a.initWeb()

	// Initialize allowed senders map
	a.loadAllowedSenders()

	log.Println("Application initialized successfully")
	return nil
}

// loadConfig loads application configuration
func (a *App) loadConfig() error {
	// Set up viper for configuration
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	// Set defaults
	viper.SetDefault("smtp.host", "0.0.0.0")
	viper.SetDefault("smtp.port", 25)
	viper.SetDefault("web.host", "0.0.0.0")
	viper.SetDefault("web.port", 8080)
	viper.SetDefault("domain", "example.com")
	viper.SetDefault("db.sslmode", "disable")
	viper.SetDefault("email_storage_path", "./emails")

	// Read config
	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Warning: Could not read config file: %v. Using defaults and environment variables.\n", err)
	}

	// Also check environment variables
	viper.AutomaticEnv()
	viper.SetEnvPrefix("EMAILSERVER")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Parse into config struct
	a.config = Config{
		SMTPHost: viper.GetString("smtp.host"),
		SMTPPort: viper.GetInt("smtp.port"),
		WebHost:  viper.GetString("web.host"),
		WebPort:  viper.GetInt("web.port"),
		Domain:   viper.GetString("domain"),
		DB: DBConfig{
			Host:     viper.GetString("db.host"),
			Port:     viper.GetInt("db.port"),
			User:     viper.GetString("db.user"),
			Password: viper.GetString("db.password"),
			DBName:   viper.GetString("db.name"),
			SSLMode:  viper.GetString("db.sslmode"),
		},
		TrustedDomains:   viper.GetStringSlice("trusted_domains"),
		JWTSecret:        viper.GetString("jwt_secret"),
		CertFile:         viper.GetString("tls.cert_file"),
		KeyFile:          viper.GetString("tls.key_file"),
		EmailStoragePath: viper.GetString("email_storage_path"),
	}

	// Create email storage directory if it doesn't exist
	if err := os.MkdirAll(a.config.EmailStoragePath, 0755); err != nil {
		return fmt.Errorf("failed to create email storage directory: %w", err)
	}

	log.Println("Configuration loaded")
	return nil
}

// connectDB establishes connection to the database
func (a *App) connectDB() error {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		a.config.DB.Host, a.config.DB.Port, a.config.DB.User,
		a.config.DB.Password, a.config.DB.DBName, a.config.DB.SSLMode)

	var err error
	a.db, err = sqlx.Connect("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	log.Println("Connected to database")
	return nil
}

// initSMTP initializes the SMTP server
func (a *App) initSMTP() {
	a.smtpBackend = &Backend{app: a}
	a.smtpServer = smtp.NewServer(a.smtpBackend)

	a.smtpServer.Addr = fmt.Sprintf("%s:%d", a.config.SMTPHost, a.config.SMTPPort)
	a.smtpServer.Domain = a.config.Domain
	a.smtpServer.ReadTimeout = 10 * time.Second
	a.smtpServer.WriteTimeout = 10 * time.Second
	a.smtpServer.MaxMessageBytes = 1024 * 1024 // 1MB
	a.smtpServer.MaxRecipients = 50
	a.smtpServer.AllowInsecureAuth = true

	// Configure TLS if certificates are provided
	if a.config.CertFile != "" && a.config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(a.config.CertFile, a.config.KeyFile)
		if err != nil {
			log.Printf("Warning: Could not load TLS certificates: %v. TLS will be disabled.\n", err)
		} else {
			a.smtpServer.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
		}
	}

	log.Println("SMTP server initialized")
}

// initWeb initializes the web server for API endpoints
func (a *App) initWeb() {
	gin.SetMode(gin.ReleaseMode)
	a.webRouter = gin.Default()

	// Public routes
	a.webRouter.POST("/api/register", a.handleUserRegistration)
	a.webRouter.POST("/api/login", a.handleUserLogin)
	a.webRouter.GET("/api/confirm-permission/:token", a.handleConfirmPermission)

	// Protected routes
	authGroup := a.webRouter.Group("/api")
	authGroup.Use(a.authMiddleware())
	{
		authGroup.POST("/mailboxes", a.handleCreateMailbox)
		authGroup.GET("/mailboxes", a.handleListMailboxes)
		authGroup.GET("/emails/:mailboxId", a.handleListEmails)
		authGroup.GET("/emails/:mailboxId/:emailId", a.handleGetEmail)
		authGroup.DELETE("/emails/:mailboxId/:emailId", a.handleDeleteEmail)
		authGroup.POST("/request-permission", a.handleRequestPermission)

		// Admin routes
		adminGroup := authGroup.Group("/admin")
		adminGroup.Use(a.adminMiddleware())
		{
			adminGroup.GET("/users", a.handleListUsers)
			adminGroup.POST("/trusted-domains", a.handleAddTrustedDomain)
			adminGroup.DELETE("/trusted-domains/:domain", a.handleRemoveTrustedDomain)
		}
	}

	log.Println("Web server initialized")
}

// loadAllowedSenders loads all approved permission requests from database
func (a *App) loadAllowedSenders() {
	a.allowedSenders = make(map[string]map[string]bool)

	var permissions []PermissionRequest
	err := a.db.Select(&permissions, `
		SELECT * FROM permission_requests 
		WHERE approved_at IS NOT NULL AND expires_at > NOW()
	`)

	if err != nil {
		log.Printf("Error loading permission requests: %v\n", err)
		return
	}

	for _, p := range permissions {
		if _, exists := a.allowedSenders[p.TargetMailbox]; !exists {
			a.allowedSenders[p.TargetMailbox] = make(map[string]bool)
		}
		a.allowedSenders[p.TargetMailbox][p.RequestorEmail] = true
	}

	log.Printf("Loaded %d allowed sender entries\n", len(permissions))
}

// isEmailAllowed checks if an email sender is allowed to send to a recipient
func (a *App) isEmailAllowed(from, to string) bool {
	// Get sender domain
	parts := strings.Split(from, "@")
	if len(parts) != 2 {
		return false
	}
	senderDomain := parts[1]

	// Check if sender domain is trusted
	for _, domain := range a.config.TrustedDomains {
		if domain == senderDomain {
			return true
		}
	}

	// Check if sender is registered user with our domain
	if strings.HasSuffix(from, "@"+a.config.Domain) {
		var count int
		err := a.db.Get(&count, "SELECT COUNT(*) FROM users WHERE email = $1 AND is_active = true", from)
		if err == nil && count > 0 {
			return true
		}
	}

	// Check if sender has explicit permission
	if allowed, exists := a.allowedSenders[to][from]; exists && allowed {
		return true
	}

	return false
}

// Run starts the application servers
func (a *App) Run() error {
	// Start SMTP server in a goroutine
	go func() {
		log.Printf("Starting SMTP server on %s\n", a.smtpServer.Addr)
		if err := a.smtpServer.ListenAndServe(); err != nil {
			log.Fatalf("SMTP server error: %v\n", err)
		}
	}()

	// Start web server in a goroutine
	go func() {
		addr := fmt.Sprintf("%s:%d", a.config.WebHost, a.config.WebPort)
		log.Printf("Starting web server on %s\n", addr)
		if err := a.webRouter.Run(addr); err != nil {
			log.Fatalf("Web server error: %v\n", err)
		}
	}()

	// Wait for termination signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down servers...")
	a.smtpServer.Close()
	log.Println("Servers stopped")

	return nil
}

// authMiddleware for protecting API routes
func (a *App) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(401, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Extract token from Bearer schema
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(401, gin.H{"error": "Invalid authorization format"})
			c.Abort()
			return
		}

		// Parse and validate token
		token, err := jwt.Parse(tokenParts[1], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(a.config.JWTSecret), nil
		})

		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			userID, ok := claims["user_id"].(string)
			if !ok {
				c.JSON(401, gin.H{"error": "Invalid token claims"})
				c.Abort()
				return
			}

			// Set user ID in context
			c.Set("userID", userID)
			c.Set("isAdmin", claims["is_admin"].(bool))
			c.Next()
		} else {
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
	}
}

// adminMiddleware ensures the user is an admin
func (a *App) adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		isAdmin, exists := c.Get("isAdmin")
		if !exists || !isAdmin.(bool) {
			c.JSON(403, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// SMTP Backend implementation

// NewSession implements smtp.Backend
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{
		app: b.app,
	}, nil
}

// AuthPlain authenticates a user with SMTP PLAIN auth
func (s *Session) AuthPlain(username, password string) error {
	var user User
	err := s.app.db.Get(&user, "SELECT * FROM users WHERE email = $1", username)
	if err != nil {
		return errors.New("authentication failed")
	}

	if !user.IsActive {
		return errors.New("authentication failed")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return errors.New("authentication failed")
	}

	return nil
}

// Mail implements smtp.Session.Mail
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	s.from = from
	return nil
}

// Rcpt implements smtp.Session.Rcpt
func (s *Session) Rcpt(to string) error {
	// Check if recipient domain is our domain
	if !strings.HasSuffix(to, "@"+s.app.config.Domain) {
		return errors.New("recipient domain not served by this server")
	}

	// Check if mailbox exists
	var count int
	err := s.app.db.Get(&count, "SELECT COUNT(*) FROM mailboxes WHERE address = $1", to)
	if err != nil || count == 0 {
		return errors.New("recipient not found")
	}

	// Check if sender is allowed
	if !s.app.isEmailAllowed(s.from, to) {
		// Special case for permission request emails
		if s.isPermissionRequest(to) {
			s.to = append(s.to, to)
			return nil
		}
		return errors.New("sender not authorized to send to this recipient")
	}

	s.to = append(s.to, to)
	return nil
}

// isPermissionRequest checks if this might be a permission request email
func (s *Session) isPermissionRequest(to string) bool {
	// This is a simplified check - in a real implementation, you might want to
	// check more attributes of the email
	if strings.HasPrefix(to, "permission-") ||
		strings.HasPrefix(to, "admin@") ||
		strings.HasPrefix(to, "permissions@") {
		return true
	}
	return false
}

// Data implements smtp.Session.Data
func (s *Session) Data(r io.Reader) error {
	if len(s.to) == 0 {
		return errors.New("no recipients specified")
	}

	// Read email data
	buf := make([]byte, s.app.smtpServer.MaxMessageBytes)
	n, err := r.Read(buf)
	if err != nil && err != io.EOF {
		return err
	}
	s.data = buf[:n]

	// Process each recipient
	for _, recipient := range s.to {
		if err := s.storeEmail(recipient); err != nil {
			log.Printf("Error storing email to %s: %v\n", recipient, err)
			// Continue with other recipients
		}
	}

	return nil
}

// storeEmail saves the email to storage and database
func (s *Session) storeEmail(recipient string) error {
	// Parse email to get subject and body
	// This is simplified - in a real implementation, you'd use a full email parsing library
	emailContent := string(s.data)

	// Extract subject (simplified)
	subject := "No Subject"
	subjectStart := strings.Index(emailContent, "Subject: ")
	if subjectStart != -1 {
		subjectEnd := strings.Index(emailContent[subjectStart:], "\r\n")
		if subjectEnd != -1 {
			subject = emailContent[subjectStart+9 : subjectStart+subjectEnd]
		}
	}

	// Extract body (simplified)
	bodyStart := strings.Index(emailContent, "\r\n\r\n")
	body := ""
	if bodyStart != -1 {
		body = emailContent[bodyStart+4:]
	}

	// Check if this is a permission request email
	if s.isPermissionRequest(recipient) {
		return s.processPermissionRequest(recipient, subject, body)
	}

	// Find recipient's mailbox
	var mailbox Mailbox
	err := s.app.db.Get(&mailbox, "SELECT * FROM mailboxes WHERE address = $1", recipient)
	if err != nil {
		return fmt.Errorf("mailbox not found: %w", err)
	}

	// Generate unique ID for email
	emailID := uuid.New().String()

	// Save email content to file
	emailPath := fmt.Sprintf("%s/%s.eml", s.app.config.EmailStoragePath, emailID)
	if err := os.WriteFile(emailPath, s.data, 0644); err != nil {
		return fmt.Errorf("failed to save email file: %w", err)
	}

	// Save email metadata to database
	_, err = s.app.db.Exec(`
		INSERT INTO emails (id, from_address, to_address, subject, body, created_at, mailbox_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, emailID, s.from, recipient, subject, body, time.Now(), mailbox.ID)

	if err != nil {
		// Clean up file if database insert fails
		os.Remove(emailPath)
		return fmt.Errorf("failed to save email metadata: %w", err)
	}

	log.Printf("Email from %s to %s stored successfully\n", s.from, recipient)
	return nil
}

// processPermissionRequest handles emails requesting permission to send
func (s *Session) processPermissionRequest(recipient, subject, body string) error {
	// Check if subject contains permission request identifier
	if !strings.Contains(strings.ToLower(subject), "permission request") {
		// Not a permission request, ignore
		return nil
	}

	// Extract target mailbox from email body
	// This is simplified - in a real implementation, you'd parse this more carefully
	targetMailbox := ""
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "target:") {
			targetMailbox = strings.TrimSpace(strings.TrimPrefix(line, "Target:"))
			break
		}
	}

	if targetMailbox == "" {
		return fmt.Errorf("invalid permission request: no target mailbox specified")
	}

	// Generate token for confirmation
	token := uuid.New().String()

	// Insert permission request
	_, err := s.app.db.Exec(`
		INSERT INTO permission_requests
		(id, requestor_email, target_mailbox, token, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, uuid.New().String(), s.from, targetMailbox, token, time.Now(), time.Now().AddDate(0, 1, 0))

	if err != nil {
		return fmt.Errorf("failed to create permission request: %w", err)
	}

	// Send confirmation email
	// In a real implementation, you'd use a proper email template
	confirmationSubject := "Permission Request Confirmation"
	confirmationBody := fmt.Sprintf(
		"A user from %s has requested permission to send emails to %s.\n\n"+
			"To approve this request, click the following link:\n\n"+
			"http://%s:%d/api/confirm-permission/%s\n\n"+
			"This request will expire in 30 days.",
		s.from, targetMailbox, s.app.config.WebHost, s.app.config.WebPort, token,
	)

	// Find mailbox owner
	var mailbox Mailbox
	err = s.app.db.Get(&mailbox, "SELECT * FROM mailboxes WHERE address = $1", targetMailbox)
	if err != nil {
		return fmt.Errorf("target mailbox not found: %w", err)
	}

	// Save confirmation email
	emailID := uuid.New().String()
	now := time.Now()
	_, err = s.app.db.Exec(`
		INSERT INTO emails (id, from_address, to_address, subject, body, created_at, mailbox_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, emailID, "system@"+s.app.config.Domain, targetMailbox, confirmationSubject, confirmationBody, now, mailbox.ID)

	if err != nil {
		return fmt.Errorf("failed to send confirmation email: %w", err)
	}

	log.Printf("Permission request from %s for %s created\n", s.from, targetMailbox)
	return nil
}

// Reset implements smtp.Session.Reset
func (s *Session) Reset() {
	s.from = ""
	s.to = []string{}
	s.data = nil
	s.currentSize = 0
}

// Logout implements smtp.Session.Logout
func (s *Session) Logout() error {
	return nil
}

// API handlers

// handleUserRegistration handles user registration
func (a *App) handleUserRegistration(c *gin.Context) {
	var reg UserRegistration
	if err := c.ShouldBindJSON(&reg); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Validate email
	if !strings.Contains(reg.Email, "@") {
		c.JSON(400, gin.H{"error": "Invalid email address"})
		return
	}

	// Check if email is from our domain or external
	isExternalDomain := true
	if strings.HasSuffix(reg.Email, "@"+a.config.Domain) {
		isExternalDomain = false
	}

	// Check if user already exists
	var count int
	err := a.db.Get(&count, "SELECT COUNT(*) FROM users WHERE email = $1", reg.Email)
	if err != nil {
		c.JSON(500, gin.H{"error": "Database error"})
		return
	}

	if count > 0 {
		c.JSON(400, gin.H{"error": "User already exists"})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(reg.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to process password"})
		return
	}

	// Create user
	userID := uuid.New().String()
	now := time.Now()
	_, err = a.db.Exec(`
		INSERT INTO users (id, email, password_hash, is_active, created_at, updated_at, is_admin, external_domain)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, userID, reg.Email, string(hashedPassword), true, now, now, false, isExternalDomain)

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create user"})
		return
	}

	// Create default mailbox for non-external users
	if !isExternalDomain {
		mailboxID := uuid.New().String()
		_, err = a.db.Exec(`
			INSERT INTO mailboxes (id, address, user_id, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5)
		`, mailboxID, reg.Email, userID, now, now)

		if err != nil {
			log.Printf("Failed to create default mailbox: %v\n", err)
			// Continue even if default mailbox creation failed
		}
	}

	c.JSON(201, gin.H{"message": "User registered successfully", "id": userID})
}

// handleUserLogin handles user login
func (a *App) handleUserLogin(c *gin.Context) {
	var login UserLogin
	if err := c.ShouldBindJSON(&login); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Get user
	var user User
	err := a.db.Get(&user, "SELECT * FROM users WHERE email = $1", login.Email)
	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(login.Password))
	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"email":    user.Email,
		"is_admin": user.IsAdmin,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString([]byte(a.config.JWTSecret))
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(200, gin.H{"token": tokenString})
}

// handleCreateMailbox handles creation of new mailboxes
func (a *App) handleCreateMailbox(c *gin.Context) {
	userID := c.GetString("userID")

	var mailboxReq MailboxCreation
	if err := c.ShouldBindJSON(&mailboxReq); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Validate mailbox address
	if !strings.HasSuffix(mailboxReq.Address, "@"+a.config.Domain) {
		c.JSON(400, gin.H{"error": "Mailbox address must use domain " + a.config.Domain})
		return
	}

	// Check if mailbox already exists
	var count int
	err := a.db.Get(&count, "SELECT COUNT(*) FROM mailboxes WHERE address = $1", mailboxReq.Address)
	if err != nil {
		c.JSON(500, gin.H{"error": "Database error"})
		return
	}

	if count > 0 {
		c.JSON(400, gin.H{"error": "Mailbox already exists"})
		return
	}

	// Create mailbox
	mailboxID := uuid.New().String()
	now := time.Now()
	_, err = a.db.Exec(`
		INSERT INTO mailboxes (id, address, user_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`, mailboxID, mailboxReq.Address, userID, now, now)

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create mailbox"})
		return
	}

	c.JSON(201, gin.H{"message": "Mailbox created successfully", "id": mailboxID})
}

// handleListMailboxes lists all mailboxes for the authenticated user
func (a *App) handleListMailboxes(c *gin.Context) {
	userID := c.GetString("userID")

	var mailboxes []Mailbox
	err := a.db.Select(&mailboxes, "SELECT * FROM mailboxes WHERE user_id = $1", userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to list mailboxes"})
		return
	}

	c.JSON(200, gin.H{"mailboxes": mailboxes})
}

// handleListEmails lists all emails for a specific mailbox
func (a *App) handleListEmails(c *gin.Context) {
	userID := c.GetString("userID")
	mailboxID := c.Param("mailboxId")

	// Verify user owns this mailbox
	var count int
	err := a.db.Get(&count, "SELECT COUNT(*) FROM mailboxes WHERE id = $1 AND user_id = $2", mailboxID, userID)
	if err != nil || count == 0 {
		c.JSON(403, gin.H{"error": "Unauthorized access to mailbox"})
		return
	}

	// Get emails
	var emails []Email
	err = a.db.Select(&emails, "SELECT * FROM emails WHERE mailbox_id = $1 ORDER BY created_at DESC", mailboxID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to list emails"})
		return
	}

	c.JSON(200, gin.H{"emails": emails})
}

// handleGetEmail gets a specific email
func (a *App) handleGetEmail(c *gin.Context) {
	userID := c.GetString("userID")
	mailboxID := c.Param("mailboxId")
	emailID := c.Param("emailId")

	// Verify user owns this mailbox
	var count int
	err := a.db.Get(&count, "SELECT COUNT(*) FROM mailboxes WHERE id = $1 AND user_id = $2", mailboxID, userID)
	if err != nil || count == 0 {
		c.JSON(403, gin.H{"error": "Unauthorized access to mailbox"})
		return
	}

	// Get email
	var email Email
	err = a.db.Get(&email, "SELECT * FROM emails WHERE id = $1 AND mailbox_id = $2", emailID, mailboxID)
	if err != nil {
		c.JSON(404, gin.H{"error": "Email not found"})
		return
	}

	// Mark as read if not already
	if email.ReadAt == nil {
		now := time.Now()
		_, err = a.db.Exec("UPDATE emails SET read_at = $1 WHERE id = $2", now, emailID)
		if err != nil {
			log.Printf("Failed to mark email as read: %v\n", err)
			// Continue even if update failed
		}
		email.ReadAt = &now
	}

	// Get full email content
	emailPath := fmt.Sprintf("%s/%s.eml", a.config.EmailStoragePath, emailID)
	content, err := os.ReadFile(emailPath)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to read email content"})
		return
	}

	c.JSON(200, gin.H{
		"email":       email,
		"raw_content": string(content),
	})
}

// handleDeleteEmail deletes a specific email
func (a *App) handleDeleteEmail(c *gin.Context) {
	userID := c.GetString("userID")
	mailboxID := c.Param("mailboxId")
	emailID := c.Param("emailId")

	// Verify user owns this mailbox
	var count int
	err := a.db.Get(&count, "SELECT COUNT(*) FROM mailboxes WHERE id = $1 AND user_id = $2", mailboxID, userID)
	if err != nil || count == 0 {
		c.JSON(403, gin.H{"error": "Unauthorized access to mailbox"})
		return
	}

	// Delete email
	_, err = a.db.Exec("DELETE FROM emails WHERE id = $1 AND mailbox_id = $2", emailID, mailboxID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to delete email"})
		return
	}

	// Delete email file
	emailPath := fmt.Sprintf("%s/%s.eml", a.config.EmailStoragePath, emailID)
	err = os.Remove(emailPath)
	if err != nil {
		log.Printf("Failed to delete email file: %v\n", err)
		// Continue even if file deletion failed
	}

	c.JSON(200, gin.H{"message": "Email deleted successfully"})
}

// handleRequestPermission creates a new permission request
func (a *App) handleRequestPermission(c *gin.Context) {
	var req PermissionRequestCreation
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Get user email
	user := User{}
	userID := c.GetString("userID")
	err := a.db.Get(&user, "SELECT * FROM users WHERE id = $1", userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to get user info"})
		return
	}

	// Check if target mailbox exists
	var count int
	err = a.db.Get(&count, "SELECT COUNT(*) FROM mailboxes WHERE address = $1", req.TargetMailbox)
	if err != nil || count == 0 {
		c.JSON(400, gin.H{"error": "Target mailbox does not exist"})
		return
	}

	// Check if permission already exists
	err = a.db.Get(&count, `
		SELECT COUNT(*) FROM permission_requests 
		WHERE requestor_email = $1 AND target_mailbox = $2 
		AND (approved_at IS NOT NULL) AND (expires_at > NOW())
	`, user.Email, req.TargetMailbox)
	if err != nil {
		c.JSON(500, gin.H{"error": "Database error"})
		return
	}

	if count > 0 {
		c.JSON(400, gin.H{"error": "Permission already granted"})
		return
	}

	// Generate token
	token := uuid.New().String()

	// Create permission request
	requestID := uuid.New().String()
	_, err = a.db.Exec(`
		INSERT INTO permission_requests
		(id, requestor_email, target_mailbox, token, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, requestID, user.Email, req.TargetMailbox, token, time.Now(), time.Now().AddDate(0, 1, 0))

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create permission request"})
		return
	}

	// Get target mailbox information
	var mailbox Mailbox
	err = a.db.Get(&mailbox, "SELECT * FROM mailboxes WHERE address = $1", req.TargetMailbox)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to get mailbox info"})
		return
	}

	// Create confirmation email
	// In a real implementation, you'd use a proper email template
	confirmationSubject := "Permission Request Confirmation"
	confirmationBody := fmt.Sprintf(
		"User %s has requested permission to send emails to %s.\n\n"+
			"To approve this request, click the following link:\n\n"+
			"http://%s:%d/api/confirm-permission/%s\n\n"+
			"This request will expire in 30 days.",
		user.Email, req.TargetMailbox, a.config.WebHost, a.config.WebPort, token,
	)

	// Save confirmation email
	emailID := uuid.New().String()
	now := time.Now()
	_, err = a.db.Exec(`
		INSERT INTO emails (id, from_address, to_address, subject, body, created_at, mailbox_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, emailID, "system@"+a.config.Domain, req.TargetMailbox, confirmationSubject, confirmationBody, now, mailbox.ID)

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to send confirmation email"})
		return
	}

	c.JSON(201, gin.H{"message": "Permission request sent"})
}

// handleConfirmPermission processes a permission confirmation
func (a *App) handleConfirmPermission(c *gin.Context) {
	token := c.Param("token")

	// Find permission request
	var req PermissionRequest
	err := a.db.Get(&req, "SELECT * FROM permission_requests WHERE token = $1", token)
	if err != nil {
		c.JSON(404, gin.H{"error": "Permission request not found"})
		return
	}

	// Check if already approved
	if req.ApprovedAt != nil {
		c.JSON(400, gin.H{"error": "Permission already approved"})
		return
	}

	// Check if expired
	if time.Now().After(req.ExpiresAt) {
		c.JSON(400, gin.H{"error": "Permission request has expired"})
		return
	}

	// Approve request
	now := time.Now()
	_, err = a.db.Exec("UPDATE permission_requests SET approved_at = $1 WHERE id = $2", now, req.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to approve permission"})
		return
	}

	// Update allowed senders cache
	if _, exists := a.allowedSenders[req.TargetMailbox]; !exists {
		a.allowedSenders[req.TargetMailbox] = make(map[string]bool)
	}
	a.allowedSenders[req.TargetMailbox][req.RequestorEmail] = true

	c.JSON(200, gin.H{"message": "Permission approved successfully"})
}

// handleListUsers lists all users (admin only)
func (a *App) handleListUsers(c *gin.Context) {
	var users []User
	err := a.db.Select(&users, "SELECT * FROM users")
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to list users"})
		return
	}

	c.JSON(200, gin.H{"users": users})
}

// handleAddTrustedDomain adds a trusted domain (admin only)
func (a *App) handleAddTrustedDomain(c *gin.Context) {
	var domain struct {
		Domain string `json:"domain" binding:"required"`
	}

	if err := c.ShouldBindJSON(&domain); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Check if domain already trusted
	for _, d := range a.config.TrustedDomains {
		if d == domain.Domain {
			c.JSON(400, gin.H{"error": "Domain already trusted"})
			return
		}
	}

	// Add to trusted domains
	a.config.TrustedDomains = append(a.config.TrustedDomains, domain.Domain)

	// In a real implementation, you'd save this to the database and/or config file

	c.JSON(201, gin.H{"message": "Domain added to trusted list"})
}

// handleRemoveTrustedDomain removes a trusted domain (admin only)
func (a *App) handleRemoveTrustedDomain(c *gin.Context) {
	domain := c.Param("domain")

	// Remove from trusted domains
	for i, d := range a.config.TrustedDomains {
		if d == domain {
			a.config.TrustedDomains = append(a.config.TrustedDomains[:i], a.config.TrustedDomains[i+1:]...)

			// In a real implementation, you'd save this to the database and/or config file

			c.JSON(200, gin.H{"message": "Domain removed from trusted list"})
			return
		}
	}

	c.JSON(404, gin.H{"error": "Domain not found in trusted list"})
}

// Main entry point
func main() {
	// Parse command line flags
	configFile := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	// Set config file path if provided
	if *configFile != "" {
		viper.SetConfigFile(*configFile)
	}

	// Create and initialize app
	app := &App{}
	if err := app.Init(); err != nil {
		log.Fatalf("Failed to initialize application: %v\n", err)
	}

	// Run app
	if err := app.Run(); err != nil {
		log.Fatalf("Application error: %v\n", err)
	}
}
