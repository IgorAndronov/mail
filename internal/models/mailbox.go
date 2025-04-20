package models

import "time"

type Mailbox struct {
	ID        string    `db:"id" json:"id"`
	Address   string    `db:"address" json:"address"`
	UserID    string    `db:"user_id" json:"user_id"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}
