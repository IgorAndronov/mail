package email

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/yourusername/emailserver/internal/config"
	"github.com/yourusername/emailserver/internal/models"
	"github.com/yourusername/emailserver/internal/storage"
	"github.com/yourusername/emailserver/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

// SMTPServer manages the SMTP server
type SMTPServer struct {
	server          *smtp.Server
	domain          string
	trustedDomains  []string
	db              *storage.Database
	fileStorage     *storage.FileStorage
	outboundService *OutboundService
	allowedSenders  map[string]map[string]bool // Map of target address -> allowed sender emails
	dkimSigner      *DKIMSigner                // DKIM signer
}

// NewSMTPServer creates a new SMTP server
func NewSMTPServer(
	cfg config.Config,
	db *storage.Database,
	fileStorage *storage.FileStorage,
	outboundService *OutboundService,
) *SMTPServer {
	// Initialize DKIM signer
	dkimSigner, err := NewDKIMSigner(cfg.Domain, cfg.DKIMSelector, cfg.DKIMPrivateKeyPath)
	if err != nil {
		log.Printf("Warning: DKIM signer initialization failed: %v. DKIM signing will be disabled.\n", err)
	}

	s := &SMTPServer{
		domain:          cfg.Domain,
		trustedDomains:  cfg.TrustedDomains,
		db:              db,
		fileStorage:     fileStorage,
		outboundService: outboundService,
		allowedSenders:  make(map[string]map[string]bool),
		dkimSigner:      dkimSigner,
	}

	// Initialize SMTP server
	s.server = smtp.NewServer(&Backend{s: s})
	s.server.Addr = fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	s.server.Domain = cfg.Domain
	s.server.ReadTimeout = 10 * time.Second
	s.server.WriteTimeout = 10 * time.Second
	s.server.MaxMessageBytes = 1024 * 1024 // 1MB
	s.server.MaxRecipients = 50
	s.server.AllowInsecureAuth = true

	// Configure TLS if certificates are provided
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			log.Printf("Warning: Could not load TLS certificates: %v. TLS will be disabled.\n", err)
		} else {
			s.server.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
		}
	}

	// Load allowed senders
	s.loadAllowedSenders()

	return s
}

// loadAllowedSenders loads all approved permission requests
func (s *SMTPServer) loadAllowedSenders() {
	permissions, err := s.db.GetApprovedPermissionRequests()
	if err != nil {
		log.Printf("Error loading permission requests: %v\n", err)
		return
	}

	for _, p := range permissions {
		if _, exists := s.allowedSenders[p.TargetMailbox]; !exists {
			s.allowedSenders[p.TargetMailbox] = make(map[string]bool)
		}
		s.allowedSenders[p.TargetMailbox][p.RequestorEmail] = true
	}

	log.Printf("Loaded %d allowed sender entries\n", len(permissions))
}

// isEmailAllowed checks if an email sender is allowed to send to a recipient
func (s *SMTPServer) isEmailAllowed(from, to string) bool {
	// Get sender domain
	parts := strings.Split(from, "@")
	if len(parts) != 2 {
		return false
	}
	senderDomain := parts[1]

	// Check if sender domain is trusted
	for _, domain := range s.trustedDomains {
		if domain == senderDomain {
			return true
		}
	}

	// Check if sender is registered user with our domain
	if strings.HasSuffix(from, "@"+s.domain) {
		user, err := s.db.GetUserByEmail(from)
		if err == nil && user.IsActive {
			return true
		}
	}

	// Check if sender has explicit permission
	if allowed, exists := s.allowedSenders[to][from]; exists && allowed {
		return true
	}

	return false
}

// isOwnDomain checks if a domain is owned by this server
func (s *SMTPServer) isOwnDomain(domain string) bool {
	if domain == s.domain {
		return true
	}

	// Check if it's in additional domains (if implemented)
	// For now, just check against the main domain
	return false
}

// Start starts the SMTP server
func (s *SMTPServer) Start() error {
	log.Printf("Starting SMTP server on %s\n", s.server.Addr)
	return s.server.ListenAndServe()
}

// Close stops the SMTP server
func (s *SMTPServer) Close() error {
	return s.server.Close()
}

// Backend implements SMTP server backend
type Backend struct {
	s *SMTPServer
}

// NewSession implements smtp.Backend
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{
		s:    b.s,
		helo: "",
		conn: c.Conn(), // Fix: Call Conn() as a function
	}, nil
}

// Session implements SMTP server session
type Session struct {
	s           *SMTPServer
	from        string
	to          []string
	data        []byte
	currentSize int
	helo        string
	conn        net.Conn
}

// Helo implements the HELO command
func (s *Session) Helo(identity string) error {
	s.helo = identity
	return nil
}

// AuthPlain authenticates a user with SMTP PLAIN auth
func (s *Session) AuthPlain(username, password string) error {
	user, err := s.s.db.GetUserByEmail(username)
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
func (s *Session) Mail(from string, _ *smtp.MailOptions) error {
	s.from = from
	return nil
}

// Rcpt implements smtp.Session.Rcpt
func (s *Session) Rcpt(to string) error {
	// Check if recipient domain is our domain
	recipientDomain := utils.GetDomainFromEmail(to)
	if !s.s.isOwnDomain(recipientDomain) {
		// External recipient - check if sender is authorized to send external emails
		if !strings.HasSuffix(s.from, "@"+s.s.domain) {
			return errors.New("only internal users can send external emails")
		}

		// Add recipient to list
		s.to = append(s.to, to)
		return nil
	}

	// Check if mailbox exists
	_, err := s.s.db.GetMailboxByAddress(to)
	if err != nil {
		return errors.New("recipient not found")
	}

	// Check if sender is allowed
	if !s.s.isEmailAllowed(s.from, to) {
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
	buf := make([]byte, s.s.server.MaxMessageBytes)
	n, err := r.Read(buf)
	if err != nil && err != io.EOF {
		return err
	}
	s.data = buf[:n]

	// For incoming emails, verify SPF, DKIM, and apply DMARC
	if s.conn != nil && !s.s.isOwnDomain(utils.GetDomainFromEmail(s.from)) {
		// Get sender IP from connection
		remoteAddr := s.conn.RemoteAddr()
		if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
			ip := tcpAddr.IP.String()

			// Check SPF
			fromDomain := utils.GetDomainFromEmail(s.from)
			spfResult, _ := SPFCheck(ip, fromDomain, s.helo)

			// Check DKIM
			dkimResult, _ := VerifyDKIMSignature(s.data)

			// Apply DMARC policy
			dmarcAction := ApplyDMARCPolicy(fromDomain, spfResult, dkimResult)

			// Add authentication results header
			authHeader := fmt.Sprintf("Authentication-Results: %s; spf=%s; dkim=%v; dmarc=%s",
				s.s.domain,
				spfResult,
				dkimResult,
				dmarcAction)

			// Prepend authentication header to email
			emailStr := string(s.data)
			headerEnd := strings.Index(emailStr, "\r\n\r\n")
			if headerEnd != -1 {
				emailStr = emailStr[:headerEnd] + "\r\n" + authHeader + emailStr[headerEnd:]
				s.data = []byte(emailStr)
			}

			// Reject if DMARC policy says so
			if dmarcAction == "reject" {
				return errors.New("message rejected by DMARC policy")
			}
		}
	}

	// Process each recipient
	for _, recipient := range s.to {
		recipientDomain := utils.GetDomainFromEmail(recipient)
		if s.s.isOwnDomain(recipientDomain) {
			// Internal recipient
			if err := s.storeEmail(recipient); err != nil {
				log.Printf("Error storing email to %s: %v\n", recipient, err)
				// Continue with other recipients
			}
		} else {
			// External recipient - sign with DKIM before sending
			if s.s.dkimSigner != nil {
				signedData, err := s.s.dkimSigner.SignMessage(s.data)
				if err != nil {
					log.Printf("Error signing email with DKIM: %v\n", err)
				} else {
					s.data = signedData
				}
			}

			// Send to external recipient
			if err := s.sendExternalEmail(recipient); err != nil {
				log.Printf("Error sending external email to %s: %v\n", recipient, err)
				return err
			}
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
	mailbox, err := s.s.db.GetMailboxByAddress(recipient)
	if err != nil {
		return fmt.Errorf("mailbox not found: %w", err)
	}

	// Generate unique ID for email
	emailID := uuid.New().String()

	// Check for attachments
	hasAttachments := strings.Contains(emailContent, "Content-Type: multipart/")

	// Save email content to file
	if err := s.s.fileStorage.SaveEmail(emailID, s.data); err != nil {
		return fmt.Errorf("failed to save email file: %w", err)
	}

	// Save email metadata to database
	email := models.Email{
		ID:             emailID,
		From:           s.from,
		To:             recipient,
		Subject:        subject,
		Body:           body,
		CreatedAt:      time.Now(),
		MailboxID:      mailbox.ID,
		HasAttachments: hasAttachments,
	}

	if err := s.s.db.CreateEmail(email); err != nil {
		// Clean up file if database insert fails
		s.s.fileStorage.DeleteEmail(emailID)
		return fmt.Errorf("failed to save email metadata: %w", err)
	}

	// Process attachments if any
	if hasAttachments {
		attachments, err := s.s.fileStorage.ExtractAttachments(s.data, emailID)
		if err != nil {
			log.Printf("Error processing attachments: %v\n", err)
			// Continue even if attachment processing fails
		} else if len(attachments) > 0 {
			// Store attachment metadata
			for _, att := range attachments {
				attachment := models.Attachment{
					ID:          uuid.New().String(),
					EmailID:     emailID,
					FileName:    att.FileName,
					ContentType: att.ContentType,
					Size:        att.Size,
					Path:        att.Path,
					CreatedAt:   time.Now(),
				}

				if err := s.s.db.CreateAttachment(attachment); err != nil {
					log.Printf("Error storing attachment metadata: %v\n", err)
					// Continue even if metadata storage fails
				}
			}
		}
	}

	log.Printf("Email from %s to %s stored successfully\n", s.from, recipient)
	return nil
}

// sendExternalEmail forwards an email to an external recipient
func (s *Session) sendExternalEmail(recipient string) error {
	// Parse email to get subject and body
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

	// Check if HTML
	isHTML := strings.Contains(emailContent, "Content-Type: text/html")

	// Send the email via the outbound service
	if err := s.s.outboundService.SendEmail(s.from, recipient, subject, body, isHTML); err != nil {
		return err
	}

	// Find the mailbox ID for the sender to store sent item
	mailbox, err := s.s.db.GetMailboxByAddress(s.from)
	if err != nil {
		log.Printf("Error finding mailbox for sent item: %v\n", err)
		return nil // Continue even if we can't store the sent item
	}

	// Save sent email to database
	emailID := uuid.New().String()
	now := time.Now()

	email := models.Email{
		ID:             emailID,
		From:           s.from,
		To:             recipient,
		Subject:        subject,
		Body:           body,
		CreatedAt:      now,
		MailboxID:      mailbox.ID,
		HasAttachments: false,
	}

	if err := s.s.db.CreateEmail(email); err != nil {
		log.Printf("Error storing sent email: %v\n", err)
		// Continue even if database insert fails, as email was already sent
	}

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

	// Create permission request
	req := models.PermissionRequest{
		ID:             uuid.New().String(),
		RequestorEmail: s.from,
		TargetMailbox:  targetMailbox,
		Token:          token,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().AddDate(0, 1, 0), // 1 month expiry
	}

	if err := s.s.db.CreatePermissionRequest(req); err != nil {
		return fmt.Errorf("failed to create permission request: %w", err)
	}

	// Find target mailbox
	mailbox, err := s.s.db.GetMailboxByAddress(targetMailbox)
	if err != nil {
		return fmt.Errorf("target mailbox not found: %w", err)
	}

	// Send confirmation email
	confirmationSubject := "Permission Request Confirmation"
	confirmationBody := fmt.Sprintf(
		"A user from %s has requested permission to send emails to %s.\n\n"+
			"To approve this request, click the following link:\n\n"+
			"http://localhost:8080/api/confirm-permission/%s\n\n"+
			"This request will expire in 30 days.",
		s.from, targetMailbox, token,
	)

	// Create email
	emailID := uuid.New().String()
	now := time.Now()

	email := models.Email{
		ID:             emailID,
		From:           "system@" + s.s.domain,
		To:             targetMailbox,
		Subject:        confirmationSubject,
		Body:           confirmationBody,
		CreatedAt:      now,
		MailboxID:      mailbox.ID,
		HasAttachments: false,
	}

	if err := s.s.db.CreateEmail(email); err != nil {
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
