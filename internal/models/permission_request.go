package models

import "time"

type PermissionRequest struct {
	ID             string     `db:"id" json:"id"`
	RequestorEmail string     `db:"requestor_email" json:"requestor_email"`
	TargetMailbox  string     `db:"target_mailbox" json:"target_mailbox"`
	Token          string     `db:"token" json:"token"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
	ApprovedAt     *time.Time `db:"approved_at" json:"approved_at"`
	ExpiresAt      time.Time  `db:"expires_at" json:"expires_at"`
}
