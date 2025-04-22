package models

import (
	"time"
)

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
	ID             string     `db:"id" json:"id"`
	From           string     `db:"from_address" json:"from"`
	To             string     `db:"to_address" json:"to"`
	Subject        string     `db:"subject" json:"subject"`
	Body           string     `db:"body" json:"body"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
	ReadAt         *time.Time `db:"read_at" json:"read_at"`
	MailboxID      string     `db:"mailbox_id" json:"mailbox_id"`
	HasAttachments bool       `db:"has_attachments" json:"has_attachments"`
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

// Attachment represents an email attachment
type Attachment struct {
	ID          string    `db:"id" json:"id"`
	EmailID     string    `db:"email_id" json:"email_id"`
	FileName    string    `db:"filename" json:"file_name"`
	ContentType string    `db:"content_type" json:"content_type"`
	Size        int64     `db:"size" json:"size"`
	Path        string    `db:"path" json:"path"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

// AttachmentInfo stores information about an attachment
type AttachmentInfo struct {
	FileName    string `json:"file_name"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Path        string `json:"path"`
}

// AttachmentResponse represents an attachment in API responses
type AttachmentResponse struct {
	ID          string    `json:"id"`
	FileName    string    `json:"file_name"`
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	EmailID     string    `json:"email_id"`
	CreatedAt   time.Time `json:"created_at"`
}
