package storage

import (
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/yourusername/emailserver/internal/config"
	"github.com/yourusername/emailserver/internal/models"
)

// Database provides database operations for the application
type Database struct {
	db *sqlx.DB
}

// NewDatabase creates a new database connection
func NewDatabase(config config.DBConfig) (*Database, error) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.User, config.Password, config.DBName, config.SSLMode)

	db, err := sqlx.Connect("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return &Database{db: db}, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	return d.db.Close()
}

// GetDB returns the underlying database connection
func (d *Database) GetDB() *sqlx.DB {
	return d.db
}

// User related methods

// CreateUser creates a new user
func (d *Database) CreateUser(user models.User) error {
	_, err := d.db.Exec(`
		INSERT INTO users (id, email, password_hash, is_active, created_at, updated_at, is_admin, external_domain)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, user.ID, user.Email, user.PasswordHash, user.IsActive, user.CreatedAt, user.UpdatedAt, user.IsAdmin, user.ExternalDomain)

	return err
}

// GetUserByEmail gets a user by email
func (d *Database) GetUserByEmail(email string) (models.User, error) {
	var user models.User
	err := d.db.Get(&user, "SELECT * FROM users WHERE email = $1", email)
	return user, err
}

// GetUserByID gets a user by ID
func (d *Database) GetUserByID(id string) (models.User, error) {
	var user models.User
	err := d.db.Get(&user, "SELECT * FROM users WHERE id = $1", id)
	return user, err
}

// ListUsers lists all users
func (d *Database) ListUsers() ([]models.User, error) {
	var users []models.User
	err := d.db.Select(&users, "SELECT * FROM users")
	return users, err
}

// Mailbox related methods

// CreateMailbox creates a new mailbox
func (d *Database) CreateMailbox(mailbox models.Mailbox) error {
	_, err := d.db.Exec(`
		INSERT INTO mailboxes (id, address, user_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`, mailbox.ID, mailbox.Address, mailbox.UserID, mailbox.CreatedAt, mailbox.UpdatedAt)

	return err
}

// GetMailboxByAddress gets a mailbox by address
func (d *Database) GetMailboxByAddress(address string) (models.Mailbox, error) {
	var mailbox models.Mailbox
	err := d.db.Get(&mailbox, "SELECT * FROM mailboxes WHERE address = $1", address)
	return mailbox, err
}

// GetMailboxesByUserID gets all mailboxes for a user
func (d *Database) GetMailboxesByUserID(userID string) ([]models.Mailbox, error) {
	var mailboxes []models.Mailbox
	err := d.db.Select(&mailboxes, "SELECT * FROM mailboxes WHERE user_id = $1", userID)
	return mailboxes, err
}

// Email related methods

// CreateEmail creates a new email
func (d *Database) CreateEmail(email models.Email) error {
	_, err := d.db.Exec(`
		INSERT INTO emails (id, from_address, to_address, subject, body, created_at, mailbox_id, has_attachments)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, email.ID, email.From, email.To, email.Subject, email.Body, email.CreatedAt, email.MailboxID, email.HasAttachments)

	return err
}

// GetEmailsByMailboxID gets all emails for a mailbox
func (d *Database) GetEmailsByMailboxID(mailboxID string) ([]models.Email, error) {
	var emails []models.Email
	err := d.db.Select(&emails, "SELECT * FROM emails WHERE mailbox_id = $1 ORDER BY created_at DESC", mailboxID)
	return emails, err
}

// GetEmailByID gets an email by ID
func (d *Database) GetEmailByID(id string) (models.Email, error) {
	var email models.Email
	err := d.db.Get(&email, "SELECT * FROM emails WHERE id = $1", id)
	return email, err
}

// MarkEmailAsRead marks an email as read
func (d *Database) MarkEmailAsRead(id string) error {
	now := time.Now()
	_, err := d.db.Exec("UPDATE emails SET read_at = $1 WHERE id = $2", now, id)
	return err
}

// DeleteEmail deletes an email
func (d *Database) DeleteEmail(id string) error {
	_, err := d.db.Exec("DELETE FROM emails WHERE id = $1", id)
	return err
}

// Permission related methods

// CreatePermissionRequest creates a new permission request
func (d *Database) CreatePermissionRequest(req models.PermissionRequest) error {
	_, err := d.db.Exec(`
		INSERT INTO permission_requests (id, requestor_email, target_mailbox, token, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, req.ID, req.RequestorEmail, req.TargetMailbox, req.Token, req.CreatedAt, req.ExpiresAt)

	return err
}

// GetPermissionRequestByToken gets a permission request by token
func (d *Database) GetPermissionRequestByToken(token string) (models.PermissionRequest, error) {
	var req models.PermissionRequest
	err := d.db.Get(&req, "SELECT * FROM permission_requests WHERE token = $1", token)
	return req, err
}

// ApprovePermissionRequest approves a permission request
func (d *Database) ApprovePermissionRequest(id string) error {
	now := time.Now()
	_, err := d.db.Exec("UPDATE permission_requests SET approved_at = $1 WHERE id = $2", now, id)
	return err
}

// GetApprovedPermissionRequests gets all approved permission requests
func (d *Database) GetApprovedPermissionRequests() ([]models.PermissionRequest, error) {
	var requests []models.PermissionRequest
	err := d.db.Select(&requests, `
		SELECT * FROM permission_requests 
		WHERE approved_at IS NOT NULL AND expires_at > NOW()
	`)
	return requests, err
}

// Attachment related methods

// CreateAttachment creates a new attachment
func (d *Database) CreateAttachment(attachment models.Attachment) error {
	_, err := d.db.Exec(`
		INSERT INTO attachments (id, email_id, filename, content_type, size, path, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, attachment.ID, attachment.EmailID, attachment.FileName, attachment.ContentType, attachment.Size, attachment.Path, attachment.CreatedAt)

	return err
}

// GetAttachmentsByEmailID gets all attachments for an email
func (d *Database) GetAttachmentsByEmailID(emailID string) ([]models.Attachment, error) {
	var attachments []models.Attachment
	err := d.db.Select(&attachments, "SELECT * FROM attachments WHERE email_id = $1", emailID)
	return attachments, err
}

// GetAttachmentByID gets an attachment by ID
func (d *Database) GetAttachmentByID(id string, emailID string) (models.Attachment, error) {
	var attachment models.Attachment
	err := d.db.Get(&attachment, "SELECT * FROM attachments WHERE id = $1 AND email_id = $2", id, emailID)
	return attachment, err
}

// UpdateEmailHasAttachments updates the has_attachments flag for an email
func (d *Database) UpdateEmailHasAttachments(emailID string, hasAttachments bool) error {
	_, err := d.db.Exec("UPDATE emails SET has_attachments = $1 WHERE id = $2", hasAttachments, emailID)
	return err
}
