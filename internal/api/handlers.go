package api

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/yourusername/emailserver/internal/auth"
	"github.com/yourusername/emailserver/internal/email"
	"github.com/yourusername/emailserver/internal/models"
	"github.com/yourusername/emailserver/internal/storage"
)

// Handler provides API request handlers
type Handler struct {
	db              *storage.Database
	fileStorage     *storage.FileStorage
	authService     *auth.Service
	outboundService *email.OutboundService
	domain          string
}

// NewHandler creates a new handler instance
func NewHandler(
	db *storage.Database,
	fileStorage *storage.FileStorage,
	authService *auth.Service,
	outboundService *email.OutboundService,
	domain string,
) *Handler {
	return &Handler{
		db:              db,
		fileStorage:     fileStorage,
		authService:     authService,
		outboundService: outboundService,
		domain:          domain,
	}
}

// Request and response types

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

// SendEmailRequest represents a request to send an email to an external address
type SendEmailRequest struct {
	From    string `json:"from" binding:"required"`
	To      string `json:"to" binding:"required"`
	Subject string `json:"subject" binding:"required"`
	Body    string `json:"body" binding:"required"`
	IsHTML  bool   `json:"is_html"`
}

// SendEmailWithAttachmentRequest represents a request to send an email with attachments
type SendEmailWithAttachmentRequest struct {
	From        string `json:"from" binding:"required"`
	To          string `json:"to" binding:"required"`
	Subject     string `json:"subject" binding:"required"`
	Body        string `json:"body" binding:"required"`
	IsHTML      bool   `json:"is_html"`
	Attachments []struct {
		FileName    string `json:"file_name"`
		ContentType string `json:"content_type"`
		Data        string `json:"data"` // Base64 encoded file data
	} `json:"attachments"`
}

// Handler functions

// HandleUserRegistration handles user registration
func (h *Handler) HandleUserRegistration(c *gin.Context) {
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
	if strings.HasSuffix(reg.Email, "@"+h.domain) {
		isExternalDomain = false
	}

	// Check if user already exists
	_, err := h.db.GetUserByEmail(reg.Email)
	if err == nil {
		c.JSON(400, gin.H{"error": "User already exists"})
		return
	}

	// Hash password
	hashedPassword, err := h.authService.HashPassword(reg.Password)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to process password"})
		return
	}

	// Create user
	userID := uuid.New().String()
	now := time.Now()
	user := models.User{
		ID:             userID,
		Email:          reg.Email,
		PasswordHash:   hashedPassword,
		IsActive:       true,
		CreatedAt:      now,
		UpdatedAt:      now,
		IsAdmin:        false,
		ExternalDomain: isExternalDomain,
	}

	if err := h.db.CreateUser(user); err != nil {
		c.JSON(500, gin.H{"error": "Failed to create user"})
		return
	}

	// Create default mailbox for non-external users
	if !isExternalDomain {
		mailboxID := uuid.New().String()
		mailbox := models.Mailbox{
			ID:        mailboxID,
			Address:   reg.Email,
			UserID:    userID,
			CreatedAt: now,
			UpdatedAt: now,
		}

		if err := h.db.CreateMailbox(mailbox); err != nil {
			log.Printf("Failed to create default mailbox: %v\n", err)
			// Continue even if default mailbox creation failed
		}
	}

	c.JSON(201, gin.H{"message": "User registered successfully", "id": userID})
}

// HandleUserLogin handles user login
func (h *Handler) HandleUserLogin(c *gin.Context) {
	var login UserLogin
	if err := c.ShouldBindJSON(&login); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Get user
	user, err := h.db.GetUserByEmail(login.Email)
	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verify password
	if err := h.authService.CheckPassword(login.Password, user.PasswordHash); err != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token
	tokenString, err := h.authService.GenerateToken(user)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(200, gin.H{"token": tokenString})
}

// HandleCreateMailbox handles creation of new mailboxes
func (h *Handler) HandleCreateMailbox(c *gin.Context) {
	userID := c.GetString("userID")

	var mailboxReq MailboxCreation
	if err := c.ShouldBindJSON(&mailboxReq); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Validate mailbox address
	if !strings.HasSuffix(mailboxReq.Address, "@"+h.domain) {
		c.JSON(400, gin.H{"error": "Mailbox address must use domain " + h.domain})
		return
	}

	// Check if mailbox already exists
	_, err := h.db.GetMailboxByAddress(mailboxReq.Address)
	if err == nil {
		c.JSON(400, gin.H{"error": "Mailbox already exists"})
		return
	}

	// Create mailbox
	mailboxID := uuid.New().String()
	now := time.Now()
	mailbox := models.Mailbox{
		ID:        mailboxID,
		Address:   mailboxReq.Address,
		UserID:    userID,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.db.CreateMailbox(mailbox); err != nil {
		c.JSON(500, gin.H{"error": "Failed to create mailbox"})
		return
	}

	c.JSON(201, gin.H{"message": "Mailbox created successfully", "id": mailboxID})
}

// HandleListMailboxes lists all mailboxes for the authenticated user
func (h *Handler) HandleListMailboxes(c *gin.Context) {
	userID := c.GetString("userID")

	mailboxes, err := h.db.GetMailboxesByUserID(userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to list mailboxes"})
		return
	}

	c.JSON(200, gin.H{"mailboxes": mailboxes})
}

// HandleListEmails lists all emails for a specific mailbox
func (h *Handler) HandleListEmails(c *gin.Context) {
	userID := c.GetString("userID")
	mailboxID := c.Param("mailboxId")

	// Verify user owns this mailbox
	mailboxes, err := h.db.GetMailboxesByUserID(userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to retrieve mailboxes"})
		return
	}

	// Check if mailbox belongs to user
	mailboxFound := false
	for _, mb := range mailboxes {
		if mb.ID == mailboxID {
			mailboxFound = true
			break
		}
	}

	if !mailboxFound {
		c.JSON(403, gin.H{"error": "Unauthorized access to mailbox"})
		return
	}

	// Get emails
	emails, err := h.db.GetEmailsByMailboxID(mailboxID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to list emails"})
		return
	}

	c.JSON(200, gin.H{"emails": emails})
}

// HandleGetEmail gets a specific email
func (h *Handler) HandleGetEmail(c *gin.Context) {
	userID := c.GetString("userID")
	mailboxID := c.Param("mailboxId")
	emailID := c.Param("emailId")

	// Verify user owns this mailbox
	mailboxes, err := h.db.GetMailboxesByUserID(userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to retrieve mailboxes"})
		return
	}

	// Check if mailbox belongs to user
	mailboxFound := false
	for _, mb := range mailboxes {
		if mb.ID == mailboxID {
			mailboxFound = true
			break
		}
	}

	if !mailboxFound {
		c.JSON(403, gin.H{"error": "Unauthorized access to mailbox"})
		return
	}

	// Get email
	email, err := h.db.GetEmailByID(emailID)
	if err != nil {
		c.JSON(404, gin.H{"error": "Email not found"})
		return
	}

	if email.MailboxID != mailboxID {
		c.JSON(404, gin.H{"error": "Email not found in this mailbox"})
		return
	}

	// Mark as read if not already
	if email.ReadAt == nil {
		if err := h.db.MarkEmailAsRead(emailID); err != nil {
			log.Printf("Failed to mark email as read: %v\n", err)
			// Continue even if update failed
		}
		now := time.Now()
		email.ReadAt = &now
	}

	// Get full email content
	content, err := h.fileStorage.GetEmail(emailID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to read email content"})
		return
	}

	c.JSON(200, gin.H{
		"email":       email,
		"raw_content": string(content),
	})
}

// HandleDeleteEmail deletes a specific email
func (h *Handler) HandleDeleteEmail(c *gin.Context) {
	userID := c.GetString("userID")
	mailboxID := c.Param("mailboxId")
	emailID := c.Param("emailId")

	// Verify user owns this mailbox
	mailboxes, err := h.db.GetMailboxesByUserID(userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to retrieve mailboxes"})
		return
	}

	// Check if mailbox belongs to user
	mailboxFound := false
	for _, mb := range mailboxes {
		if mb.ID == mailboxID {
			mailboxFound = true
			break
		}
	}

	if !mailboxFound {
		c.JSON(403, gin.H{"error": "Unauthorized access to mailbox"})
		return
	}

	// Get email to verify it belongs to the mailbox
	email, err := h.db.GetEmailByID(emailID)
	if err != nil {
		c.JSON(404, gin.H{"error": "Email not found"})
		return
	}

	if email.MailboxID != mailboxID {
		c.JSON(404, gin.H{"error": "Email not found in this mailbox"})
		return
	}

	// Delete email
	if err := h.db.DeleteEmail(emailID); err != nil {
		c.JSON(500, gin.H{"error": "Failed to delete email"})
		return
	}

	// Delete email file
	if err := h.fileStorage.DeleteEmail(emailID); err != nil {
		log.Printf("Failed to delete email file: %v\n", err)
		// Continue even if file deletion failed
	}

	// Delete attachments if any
	if email.HasAttachments {
		if err := h.fileStorage.DeleteAttachmentsForEmail(emailID); err != nil {
			log.Printf("Failed to delete email attachments: %v\n", err)
			// Continue even if attachment deletion failed
		}
	}

	c.JSON(200, gin.H{"message": "Email deleted successfully"})
}

// HandleRequestPermission creates a new permission request
func (h *Handler) HandleRequestPermission(c *gin.Context) {
	var req PermissionRequestCreation
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Get user email
	userID := c.GetString("userID")
	user, err := h.db.GetUserByID(userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to get user info"})
		return
	}

	// Check if target mailbox exists
	_, err = h.db.GetMailboxByAddress(req.TargetMailbox)
	if err != nil {
		c.JSON(400, gin.H{"error": "Target mailbox does not exist"})
		return
	}

	// Check if permission already exists
	permissions, err := h.db.GetApprovedPermissionRequests()
	if err != nil {
		c.JSON(500, gin.H{"error": "Database error"})
		return
	}

	for _, perm := range permissions {
		if perm.RequestorEmail == user.Email && perm.TargetMailbox == req.TargetMailbox {
			c.JSON(400, gin.H{"error": "Permission already granted"})
			return
		}
	}

	// Generate token
	token := uuid.New().String()

	// Create permission request
	requestID := uuid.New().String()
	permReq := models.PermissionRequest{
		ID:             requestID,
		RequestorEmail: user.Email,
		TargetMailbox:  req.TargetMailbox,
		Token:          token,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().AddDate(0, 1, 0), // 1 month expiry
	}

	if err := h.db.CreatePermissionRequest(permReq); err != nil {
		c.JSON(500, gin.H{"error": "Failed to create permission request"})
		return
	}

	// Get target mailbox information
	mailbox, err := h.db.GetMailboxByAddress(req.TargetMailbox)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to get mailbox info"})
		return
	}

	// Create confirmation email
	confirmationSubject := "Permission Request Confirmation"
	confirmationBody := fmt.Sprintf(
		"User %s has requested permission to send emails to %s.\n\n"+
			"To approve this request, click the following link:\n\n"+
			"http://localhost:8080/api/confirm-permission/%s\n\n"+
			"This request will expire in 30 days.",
		user.Email, req.TargetMailbox, token,
	)

	// Save confirmation email
	emailID := uuid.New().String()
	now := time.Now()

	email := models.Email{
		ID:             emailID,
		From:           "system@" + h.domain,
		To:             req.TargetMailbox,
		Subject:        confirmationSubject,
		Body:           confirmationBody,
		CreatedAt:      now,
		MailboxID:      mailbox.ID,
		HasAttachments: false,
	}

	if err := h.db.CreateEmail(email); err != nil {
		c.JSON(500, gin.H{"error": "Failed to send confirmation email"})
		return
	}

	c.JSON(201, gin.H{"message": "Permission request sent"})
}

// HandleConfirmPermission processes a permission confirmation
func (h *Handler) HandleConfirmPermission(c *gin.Context) {
	token := c.Param("token")

	// Find permission request
	req, err := h.db.GetPermissionRequestByToken(token)
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
	if err := h.db.ApprovePermissionRequest(req.ID); err != nil {
		c.JSON(500, gin.H{"error": "Failed to approve permission"})
		return
	}

	c.JSON(200, gin.H{"message": "Permission approved successfully"})
}

// HandleSendExternalEmail sends an email to an external recipient
func (h *Handler) HandleSendExternalEmail(c *gin.Context) {
	userID := c.GetString("userID")

	var req SendEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Verify user owns this mailbox
	mailboxes, err := h.db.GetMailboxesByUserID(userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to retrieve mailboxes"})
		return
	}

	// Check if mailbox belongs to user
	mailboxFound := false
	var userMailbox models.Mailbox
	for _, mb := range mailboxes {
		if mb.Address == req.From {
			mailboxFound = true
			userMailbox = mb
			break
		}
	}

	if !mailboxFound {
		c.JSON(403, gin.H{"error": "You can only send from your own email addresses"})
		return
	}

	//// Check if recipient is external
	//if !email.IsExternalEmail(req.To, h.domain) {
	//	c.JSON(400, gin.H{"error": "Use internal email sending for recipients on " + h.domain})
	//	return
	//}

	// Send the email
	err = h.outboundService.SendEmail(req.From, req.To, req.Subject, req.Body, req.IsHTML)
	if err != nil {
		log.Printf("Failed to send external email: %v\n", err)
		c.JSON(500, gin.H{"error": "Failed to send email: " + err.Error()})
		return
	}

	// Store a record of the sent email
	emailID := uuid.New().String()
	now := time.Now()

	// Save email metadata to database (in sent items)
	email := models.Email{
		ID:             emailID,
		From:           req.From,
		To:             req.To,
		Subject:        req.Subject,
		Body:           req.Body,
		CreatedAt:      now,
		MailboxID:      userMailbox.ID,
		HasAttachments: false,
	}

	if err := h.db.CreateEmail(email); err != nil {
		log.Printf("Error storing sent email: %v\n", err)
		// Continue even if database insert fails, as email was already sent
	}

	c.JSON(200, gin.H{
		"message": "Email sent successfully",
		"id":      emailID,
	})
}

// HandleSendEmailWithAttachment handles sending emails with attachments
func (h *Handler) HandleSendEmailWithAttachment(c *gin.Context) {
	userID := c.GetString("userID")

	var req SendEmailWithAttachmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Verify user owns this mailbox
	mailboxes, err := h.db.GetMailboxesByUserID(userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to retrieve mailboxes"})
		return
	}

	// Check if mailbox belongs to user
	mailboxFound := false
	var userMailbox models.Mailbox
	for _, mb := range mailboxes {
		if mb.Address == req.From {
			mailboxFound = true
			userMailbox = mb
			break
		}
	}

	if !mailboxFound {
		c.JSON(403, gin.H{"error": "You can only send from your own email addresses"})
		return
	}

	// Check if this is an internal or external recipient
	isExternal := email.IsExternalEmail(req.To, h.domain)

	// Generate unique email ID
	emailID := uuid.New().String()

	// Process attachments if any
	var attachments []models.AttachmentInfo
	if len(req.Attachments) > 0 {
		// Save each attachment to disk
		for i, attachment := range req.Attachments {
			// Decode base64 data
			data, err := base64.StdEncoding.DecodeString(attachment.Data)
			if err != nil {
				c.JSON(400, gin.H{"error": fmt.Sprintf("Invalid base64 data for attachment %d", i+1)})
				return
			}

			// Save attachment
			filename := filepath.Base(attachment.FileName)
			if filename == "" {
				filename = fmt.Sprintf("attachment-%d", i+1)
			}

			// Save to file
			path, err := h.fileStorage.SaveAttachment(emailID, filename, data)
			if err != nil {
				c.JSON(500, gin.H{"error": fmt.Sprintf("Failed to save attachment %d", i+1)})
				return
			}

			// Add to attachments list
			attachments = append(attachments, models.AttachmentInfo{
				FileName:    filename,
				ContentType: attachment.ContentType,
				Size:        int64(len(data)),
				Path:        path,
			})
		}
	}

	// Save email to database
	now := time.Now()
	hasAttachments := len(attachments) > 0

	// Insert email into database
	email := models.Email{
		ID:             emailID,
		From:           req.From,
		To:             req.To,
		Subject:        req.Subject,
		Body:           req.Body,
		CreatedAt:      now,
		MailboxID:      userMailbox.ID,
		HasAttachments: hasAttachments,
	}

	if err := h.db.CreateEmail(email); err != nil {
		c.JSON(500, gin.H{"error": "Failed to store email"})
		return
	}

	// Save attachments metadata if any
	if hasAttachments {
		for _, attachment := range attachments {
			attachmentID := uuid.New().String()

			dbAttachment := models.Attachment{
				ID:          attachmentID,
				EmailID:     emailID,
				FileName:    attachment.FileName,
				ContentType: attachment.ContentType,
				Size:        attachment.Size,
				Path:        attachment.Path,
				CreatedAt:   now,
			}

			if err := h.db.CreateAttachment(dbAttachment); err != nil {
				log.Printf("Error storing attachment metadata: %v\n", err)
				// Continue even if we fail to store some attachment metadata
			}
		}

		// Create email content
		var fullEmail []byte
		if isExternal {
			// If recipient is external, we'll send via gomail, no need to create full email content
		} else {
			// Create full email content for internal storage
			boundary := "==EmailServerBoundary_" + emailID
			multipartMessage, err := h.fileStorage.CreateMultipartMessage(req.Body, req.IsHTML, attachments, boundary)
			if err != nil {
				log.Printf("Error creating multipart message: %v\n", err)
			} else {
				// Prepare email headers
				headers := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\n",
					req.From, req.To, req.Subject, now.Format(time.RFC1123Z))

				// Combine headers and body
				fullEmail = []byte(headers + multipartMessage)

				// Write to file
				if err := h.fileStorage.SaveEmail(emailID, fullEmail); err != nil {
					log.Printf("Error writing email file: %v\n", err)
				}
			}
		}
	}

	// If recipient is external, send via outbound service
	if isExternal {
		if hasAttachments {
			// Prepare attachments for gomail
			mailAttachments := make([]struct {
				Path        string
				Name        string
				ContentType string
			}, len(attachments))

			for i, att := range attachments {
				mailAttachments[i] = struct {
					Path        string
					Name        string
					ContentType string
				}{
					Path:        att.Path,
					Name:        att.FileName,
					ContentType: att.ContentType,
				}
			}

			// Send with attachments
			err = h.outboundService.SendEmailWithAttachments(req.From, req.To, req.Subject, req.Body, req.IsHTML, mailAttachments)
		} else {
			// Send without attachments
			err = h.outboundService.SendEmail(req.From, req.To, req.Subject, req.Body, req.IsHTML)
		}

		if err != nil {
			log.Printf("Failed to send external email: %v\n", err)
			c.JSON(500, gin.H{"error": "Failed to send email: " + err.Error()})
			return
		}
	}

	c.JSON(200, gin.H{
		"message": "Email sent successfully",
		"id":      emailID,
	})
}

// HandleGetEmailAttachments gets a list of attachments for an email
func (h *Handler) HandleGetEmailAttachments(c *gin.Context) {
	userID := c.GetString("userID")
	mailboxID := c.Param("mailboxId")
	emailID := c.Param("emailId")

	// Verify user owns this mailbox
	mailboxes, err := h.db.GetMailboxesByUserID(userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to retrieve mailboxes"})
		return
	}

	// Check if mailbox belongs to user
	mailboxFound := false
	for _, mb := range mailboxes {
		if mb.ID == mailboxID {
			mailboxFound = true
			break
		}
	}

	if !mailboxFound {
		c.JSON(403, gin.H{"error": "Unauthorized access to mailbox"})
		return
	}

	// Get email to verify it belongs to the mailbox
	email, err := h.db.GetEmailByID(emailID)
	if err != nil {
		c.JSON(404, gin.H{"error": "Email not found"})
		return
	}

	if email.MailboxID != mailboxID {
		c.JSON(404, gin.H{"error": "Email not found in this mailbox"})
		return
	}

	// Get attachments
	attachments, err := h.db.GetAttachmentsByEmailID(emailID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to list attachments"})
		return
	}

	// Convert to response objects (remove file paths for security)
	var response []models.AttachmentResponse
	for _, att := range attachments {
		response = append(response, models.AttachmentResponse{
			ID:          att.ID,
			FileName:    att.FileName,
			ContentType: att.ContentType,
			Size:        att.Size,
			EmailID:     att.EmailID,
			CreatedAt:   att.CreatedAt,
		})
	}

	c.JSON(200, gin.H{"attachments": response})
}

// HandleDownloadAttachment downloads a specific attachment
func (h *Handler) HandleDownloadAttachment(c *gin.Context) {
	userID := c.GetString("userID")
	mailboxID := c.Param("mailboxId")
	emailID := c.Param("emailId")
	attachmentID := c.Param("attachmentId")

	// Verify user owns this mailbox
	mailboxes, err := h.db.GetMailboxesByUserID(userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to retrieve mailboxes"})
		return
	}

	// Check if mailbox belongs to user
	mailboxFound := false
	for _, mb := range mailboxes {
		if mb.ID == mailboxID {
			mailboxFound = true
			break
		}
	}

	if !mailboxFound {
		c.JSON(403, gin.H{"error": "Unauthorized access to mailbox"})
		return
	}

	// Get email to verify it belongs to the mailbox
	email, err := h.db.GetEmailByID(emailID)
	if err != nil {
		c.JSON(404, gin.H{"error": "Email not found"})
		return
	}

	if email.MailboxID != mailboxID {
		c.JSON(404, gin.H{"error": "Email not found in this mailbox"})
		return
	}

	// Get attachment
	attachment, err := h.db.GetAttachmentByID(attachmentID, emailID)
	if err != nil {
		c.JSON(404, gin.H{"error": "Attachment not found"})
		return
	}

	// Check if file exists
	if _, err := os.Stat(attachment.Path); os.IsNotExist(err) {
		c.JSON(404, gin.H{"error": "Attachment file not found"})
		return
	}

	// Serve the file
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", attachment.FileName))
	c.Header("Content-Type", attachment.ContentType)
	c.File(attachment.Path)
}

// HandleListUsers lists all users (admin only)
func (h *Handler) HandleListUsers(c *gin.Context) {
	users, err := h.db.ListUsers()
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to list users"})
		return
	}

	c.JSON(200, gin.H{"users": users})
}

// HandleAddTrustedDomain adds a trusted domain (admin only)
func (h *Handler) HandleAddTrustedDomain(c *gin.Context) {
	var domain struct {
		Domain string `json:"domain" binding:"required"`
	}

	if err := c.ShouldBindJSON(&domain); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// In a real implementation, you'd save this to the database

	c.JSON(201, gin.H{"message": "Domain added to trusted list"})
}

// HandleRemoveTrustedDomain removes a trusted domain (admin only)
func (h *Handler) HandleRemoveTrustedDomain(c *gin.Context) {
	//domain := c.Param("domain")

	// In a real implementation, you'd remove this from the database

	c.JSON(200, gin.H{"message": "Domain removed from trusted list"})
}
