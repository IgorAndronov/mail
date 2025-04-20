package models

import "time"

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
